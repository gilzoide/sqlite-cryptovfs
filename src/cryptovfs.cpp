#include <cassert>
#include <cstring>
#include <cstdint>

#include <sodium.h>
#include <sqlite3.h>
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1
#include <SQLiteVfs.hpp>

#include "cryptovfs.h"
#include "sodium_memory.hpp"
#include "sqlite_memory.hpp"
#include "utils.hpp"

// SQLite file format offsets
#define SQLITE_FORMAT_HEADER_STRING "SQLite format 3"
#define SQLITE_FORMAT_PAGE_SIZE_OFFSET 16
#define SQLITE_FORMAT_RESERVED_BYTES_OFFSET 20
#define SQLITE_FORMAT_WAL_HEADER_SIZE 24

// Constant byte sizes
static const int CRYPTOVFS_KEY_BYTES = crypto_kdf_KEYBYTES;
static const int CRYPTOVFS_SUBKEY_BYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
static const int CRYPTOVFS_NONCE_BYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
static const int CRYPTOVFS_SALT_BYTES = crypto_pwhash_SALTBYTES;
static const int CRYPTOVFS_MAC_BYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;
// With 8 byte nonces, we can securely write 2^64 times into the same page.
static const int CRYPTOVFS_DEFAULT_RESERVED_BYTES = CRYPTOVFS_MAC_BYTES + 8;
static const int CRYPTOVFS_HEADER_UNENCRYPTED_BYTES = 24;
static_assert(CRYPTOVFS_SALT_BYTES == sizeof(SQLITE_FORMAT_HEADER_STRING), "Salt has different byte size than SQLite format header string");

// Helper macros for byte/math operations
#define LOAD_8(p) \
	(((uint8_t *) p)[0])
#define LOAD_16_BE(p) \
	((((uint8_t *) p)[0] << 8) + (((uint8_t *) p)[1]))
#define LOAD_32_BE(p) \
	((((uint8_t *) p)[0] << 24) + (((uint8_t *) p)[1] << 16) + (((uint8_t *) p)[2] << 8) + (((uint8_t *) p)[3]))
#define MIN(a, b) \
	((a) < (b) ? (a) : (b))
#define MAX(a, b) \
	((a) > (b) ? (a) : (b))

// Helper logic macros
#define STARTS_WITH(buffer, literal_string) \
	(memcmp((buffer), (literal_string), sizeof(literal_string) - 1) == 0)
#define RETURN_IF_NOT_OK(statement) \
	{ \
		int result = statement; \
		if (result != SQLITE_OK) { \
			return result; \
		} \
	}

using namespace sqlitevfs;

namespace cryptovfs {

enum class EncryptedFileType {
	Db,
	Journal,
	Wal,
	Temp,
};

enum class IoOp {
	Read,
	Write,
};

struct EncryptedFile : public SQLiteFileImpl {
	// Keys are stored in secure memory (reference: https://doc.libsodium.org/memory_management)
	SodiumMemory<char> text_key = nullptr;
	SodiumMemory<unsigned char> key = nullptr;
	SodiumMemory<unsigned char> subkey = nullptr;

	SQLiteMemory<unsigned char> salt = nullptr;
	SQLiteMemory<unsigned char> encryption_buffer = nullptr;
	unsigned char nonce_buffer[CRYPTOVFS_NONCE_BYTES];
	int page_size = 0;
	int reserved_bytes = 0;
	uint32_t page_number;
	EncryptedFileType file_type;
	EncryptedFile *main_db_file;
	bool file_contains_sqlite_header = false;

	void setup(sqlite3_filename zName, int flags) {
		if (flags & SQLITE_OPEN_MAIN_DB) {
			file_type = EncryptedFileType::Db;
			main_db_file = this;
		}
		else if (flags & SQLITE_OPEN_MAIN_JOURNAL) {
			file_type = EncryptedFileType::Journal;
			main_db_file = &((SQLiteFile<EncryptedFile> *) sqlite3_database_file_object(zName))->implementation;
		}
		else if (flags & SQLITE_OPEN_WAL) {
			file_type = EncryptedFileType::Wal;
			main_db_file = &((SQLiteFile<EncryptedFile> *) sqlite3_database_file_object(zName))->implementation;
		}
		else {
			file_type = EncryptedFileType::Temp;
			main_db_file = nullptr;
		}

		if (const char *textkey_uri = sqlite3_uri_parameter(zName, "textkey")) {
			set_text_key(const_cast<char *>(textkey_uri));
		}
		if (const char *key_uri = sqlite3_uri_parameter(zName, "key")) {
			set_key(const_cast<char *>(key_uri));
		}
		if (const char *hexkey_uri = sqlite3_uri_parameter(zName, "hexkey")) {
			set_hex_key(const_cast<char *>(hexkey_uri));
		}
	}

	int xRead(void *p, int iAmt, sqlite3_int64 iOfst) override {
		RETURN_IF_NOT_OK(SQLiteFileImpl::xRead(p, iAmt, iOfst));
		if (!is_encrypted()) {
			return SQLITE_OK;
		}

		switch (file_type) {
			case EncryptedFileType::Db:
				if (iOfst == 0 && iAmt >= CRYPTOVFS_HEADER_UNENCRYPTED_BYTES) {
					process_db_header(p, iAmt, IoOp::Read);
					// the file is not actually encrypted, just skip decryption
					if (file_contains_sqlite_header) {
						return SQLITE_OK;
					}
				}
				RETURN_IF_NOT_OK(fill_page_number(p, iAmt, iOfst, IoOp::Read));
				assert(page_size > 0 && "FIXME: page size was not read yet");
				// make sure we read the whole page before decrypting
				if (iAmt != page_size) {
					assert(iOfst / page_size == 0 && "FIXME: SQLite is partially reading something that is not in the first page");
					encryption_buffer.resize_at_least(page_size);
					RETURN_IF_NOT_OK(SQLiteFileImpl::xRead(encryption_buffer, page_size, 0));

					if (const void *data = decrypt_page(encryption_buffer, page_size, page_number)) {
						memcpy(p, encryption_buffer.ptr() + iOfst, iAmt);
					}
					else {
						return SQLITE_IOERR_READ;
					}
				}
				else {
					if (const void *data = decrypt_page((const unsigned char *) p, iAmt, page_number)) {
						memcpy(p, encryption_buffer.ptr(), iAmt);
					}
					else {
						return SQLITE_IOERR_READ;
					}
				}
				break;

			case EncryptedFileType::Journal:
			case EncryptedFileType::Wal:
				RETURN_IF_NOT_OK(fill_page_number(p, iAmt, iOfst, IoOp::Read));
				if (iAmt == main_db_file->page_size) {
					if (const void *data = decrypt_page((const unsigned char *) p, iAmt, page_number)) {
						memcpy(p, data, iAmt);
					}
					else {
						return SQLITE_IOERR_READ;
					}
				}
				break;

			default:
				break;
		}

		return SQLITE_OK;
	}

	int xWrite(const void *p, int iAmt, sqlite3_int64 iOfst) override {
		if (is_encrypted()) {
			switch (file_type) {
				case EncryptedFileType::Db:
					if (iOfst == 0 && iAmt >= CRYPTOVFS_HEADER_UNENCRYPTED_BYTES) {
						process_db_header(p, iAmt, IoOp::Write);
					}
					assert(iAmt == page_size && "Writing to database with a different page size");
					RETURN_IF_NOT_OK(fill_page_number(p, iAmt, iOfst, IoOp::Write));
					p = encrypt_page((unsigned char *) p, iAmt, page_number);
					break;

				case EncryptedFileType::Journal:
				case EncryptedFileType::Wal:
					RETURN_IF_NOT_OK(fill_page_number(p, iAmt, iOfst, IoOp::Write));
					if (iOfst != 0 && iAmt == main_db_file->page_size) {
						p = encrypt_page((unsigned char *) p, iAmt, page_number);
					}
					break;

				default:
					break;
			}

			if (p == nullptr) {
				return SQLITE_IOERR_WRITE;
			}
		}

		return SQLiteFileImpl::xWrite(p, iAmt, iOfst);
	}

	int xFileControl(int op, void *pArg) override {
		switch (op) {
			case SQLITE_FCNTL_PRAGMA: {
				char **args = (char **) pArg;
				if (args[2] && strcasecmp(args[1], "textkey") == 0) {
					set_text_key(args[2]);
					return SQLITE_OK;
				}
				else if (args[2] && strcasecmp(args[1], "hexkey") == 0) {
					set_hex_key(args[2]);
					return SQLITE_OK;
				}
				else if (args[2] && strcasecmp(args[1], "key") == 0) {
					set_key(args[2]);
					return SQLITE_OK;
				}
				break;
			}
		}
		return SQLiteFileImpl::xFileControl(op, pArg);
	}

private:
	bool is_encrypted() const {
		return main_db_file
			&& !main_db_file->file_contains_sqlite_header
			&& (main_db_file->key || main_db_file->text_key);
	}

	void set_text_key(char *textkey) {
		size_t length = strlen(textkey);
		text_key = SodiumMemory<char>(textkey, length + 1);
		memset(textkey, '*', length);
		// free key to force reload it from textkey next time encryption is used
		key.free();
	}

	void set_hex_key(char *hexkey) {
		if (!key) {
			key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
		}
		size_t hexkey_length = strlen(hexkey);
		size_t binlen = 1;
		for (int i = 0; i < CRYPTOVFS_KEY_BYTES && binlen > 0; i += binlen) {
			sodium_hex2bin(key.ptr() + i, CRYPTOVFS_KEY_BYTES - i, hexkey, hexkey_length, ":", &binlen, NULL);
		}
		memset(hexkey, '*', hexkey_length);
	}

	void set_key(char *newkey) {
		if (!key) {
			key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
		}
		size_t newkey_length = strlen(newkey);
		size_t batch_size;
		for (int i = 0; i < CRYPTOVFS_KEY_BYTES; i += batch_size) {
			batch_size = MIN(CRYPTOVFS_KEY_BYTES - i, newkey_length);
			memcpy(key.ptr() + i, newkey, batch_size);
		}
		memset(newkey, '*', newkey_length);
	}

	void process_db_header(const void *p, int size, IoOp ioop) {
		assert(size >= CRYPTOVFS_HEADER_UNENCRYPTED_BYTES);
		page_size = LOAD_16_BE(p + SQLITE_FORMAT_PAGE_SIZE_OFFSET);
		if (page_size == 1) {
			page_size = 65536;
		}
		reserved_bytes = LOAD_8(p + SQLITE_FORMAT_RESERVED_BYTES_OFFSET);

		if (ioop == IoOp::Read) {
			file_contains_sqlite_header = STARTS_WITH(p, SQLITE_FORMAT_HEADER_STRING);
			if (!file_contains_sqlite_header) {
				salt = SQLiteMemory<unsigned char>((const unsigned char *) p, CRYPTOVFS_SALT_BYTES);
			}
		}
	}

	const void *encrypt_page(const unsigned char *p, int iAmt, uint32_t page_number) {
		encryption_buffer.resize_at_least(iAmt);

		int written_bytes;
		if (page_number == 1) {
			// 1st page: store the salt in place of "SQLite format 3" and skip page size and reserved bytes
			memcpy(encryption_buffer.ptr(), main_db_file->get_or_generate_salt(), CRYPTOVFS_SALT_BYTES);
			memcpy(encryption_buffer.ptr() + CRYPTOVFS_SALT_BYTES, p + CRYPTOVFS_SALT_BYTES, CRYPTOVFS_HEADER_UNENCRYPTED_BYTES - CRYPTOVFS_SALT_BYTES);
			written_bytes = CRYPTOVFS_HEADER_UNENCRYPTED_BYTES;
		}
		else {
			written_bytes = 0;
		}

		int reserved_bytes = main_db_file->reserved_bytes;
		if (reserved_bytes > CRYPTOVFS_MAC_BYTES) {
			int nonce_size = reserved_bytes - CRYPTOVFS_MAC_BYTES;
			unsigned char *nonce = fill_nonce(p + iAmt - nonce_size, nonce_size, true);
			int result = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
				encryption_buffer.ptr() + written_bytes,
				encryption_buffer.ptr() + iAmt - reserved_bytes, nullptr,
				p + written_bytes, iAmt - written_bytes - reserved_bytes,
				nullptr, 0,
				nullptr,
				nonce,
				main_db_file->get_key(page_number)
			);
			if (result != 0) {
				return nullptr;
			}
			// write nonce into buffer
			memcpy(encryption_buffer.ptr() + iAmt - nonce_size, nonce, MIN(nonce_size, CRYPTOVFS_NONCE_BYTES));
		}
		else {
			int nonce_size = reserved_bytes;
			unsigned char *nonce = fill_nonce(p + iAmt - nonce_size, nonce_size, true);
			int result = crypto_stream_chacha20_ietf_xor(
				encryption_buffer.ptr() + written_bytes,
				p + written_bytes, iAmt - written_bytes - reserved_bytes,
				nonce,
				main_db_file->get_key(page_number)
			);
			if (result != 0) {
				return nullptr;
			}
			// write nonce into buffer
			memcpy(encryption_buffer.ptr() + iAmt - nonce_size, nonce, MIN(nonce_size, CRYPTOVFS_NONCE_BYTES));
		}
		return encryption_buffer;
	}

	const void *decrypt_page(const unsigned char *encrypted_page, int iAmt, uint32_t page_number) {
		encryption_buffer.resize_at_least(iAmt);

		int written_bytes;
		if (page_number == 1) {
			memcpy(encryption_buffer.ptr(), SQLITE_FORMAT_HEADER_STRING, sizeof(SQLITE_FORMAT_HEADER_STRING));
			memcpy(encryption_buffer.ptr() + sizeof(SQLITE_FORMAT_HEADER_STRING), encrypted_page + sizeof(SQLITE_FORMAT_HEADER_STRING), CRYPTOVFS_HEADER_UNENCRYPTED_BYTES - sizeof(SQLITE_FORMAT_HEADER_STRING));
			written_bytes = CRYPTOVFS_HEADER_UNENCRYPTED_BYTES;
		}
		else {
			written_bytes = 0;
		}

		int reserved_bytes = main_db_file->reserved_bytes;
		if (reserved_bytes > CRYPTOVFS_MAC_BYTES) {
			int nonce_size = reserved_bytes - CRYPTOVFS_MAC_BYTES;
			unsigned char *nonce = fill_nonce(encrypted_page + iAmt - nonce_size, nonce_size, false);
			int result = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
				encryption_buffer.ptr() + written_bytes,
				nullptr,
				encrypted_page + written_bytes, iAmt - written_bytes - reserved_bytes,
				encrypted_page + iAmt - reserved_bytes,
				nullptr, 0,
				nonce,
				main_db_file->get_key(page_number)
			);
			if (result != 0) {
				return nullptr;
			}
		}
		else {
			int nonce_size = reserved_bytes;
			unsigned char *nonce = fill_nonce(encrypted_page + iAmt - nonce_size, nonce_size, false);
			int result = crypto_stream_chacha20_ietf_xor(
				encryption_buffer.ptr() + written_bytes,
				encrypted_page + written_bytes, iAmt - written_bytes - reserved_bytes,
				nonce,
				main_db_file->get_key(page_number)
			);
			if (result != 0) {
				return nullptr;
			}
		}
		return encryption_buffer;
	}

	unsigned char *get_or_generate_salt() {
		if (!salt) {
			salt.resize(CRYPTOVFS_SALT_BYTES);
			randombytes_buf(salt, CRYPTOVFS_SALT_BYTES);
		}
		return salt;
	}

	unsigned char *fill_nonce(const unsigned char *buffer, int nonce_size, bool is_write) {
		int unset_bytes;
		if (nonce_size > CRYPTOVFS_NONCE_BYTES) {
			nonce_size = CRYPTOVFS_NONCE_BYTES;
			unset_bytes = 0;
		}
		else {
			unset_bytes = CRYPTOVFS_NONCE_BYTES - nonce_size;
		}

		if (is_all_zeros(buffer, nonce_size)) {
			assert(is_write && "FIXME: Reading nonce should never have all zeros");
			randombytes_buf(nonce_buffer, nonce_size);
		}
		else {
			memcpy(nonce_buffer, buffer, nonce_size);
			if (is_write) {
				sodium_increment(nonce_buffer, nonce_size);
			}
		}
		if (unset_bytes > 0) {
			memset(nonce_buffer + nonce_size, 0, unset_bytes);
		}
		return nonce_buffer;
	}

	unsigned char *get_key(uint64_t page_number) {
		if (!key) {
			if (text_key) {
				key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
				int result = crypto_pwhash(
					key, CRYPTOVFS_KEY_BYTES,
					text_key, text_key.size(),
					get_or_generate_salt(),
					crypto_pwhash_OPSLIMIT_MODERATE,
					crypto_pwhash_MEMLIMIT_MODERATE,
					crypto_pwhash_ALG_DEFAULT
				);
				if (result != 0) {
					key.free();
					return nullptr;
				}
				text_key.free();
			}
			else {
				return nullptr;
			}
		}
		if (!subkey) {
			subkey = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_SUBKEY_BYTES);
		}
		int result = crypto_kdf_derive_from_key(subkey, CRYPTOVFS_SUBKEY_BYTES, page_number, (const char *) salt.ptr(), key);
		if (result == 0) {
			return subkey;
		}
		else {
			return nullptr;
		}
	}

	int fill_page_number(const void *p, int iAmt, sqlite3_int64 iOfst, IoOp ioop) {
		switch (file_type) {
			case EncryptedFileType::Db:
				assert(page_size > 0 && "FIXME: trying to find page number before reading page size");
				page_number = (iOfst / page_size) + 1;
				break;

			case EncryptedFileType::Journal:
				// SQLite always reads/writes the page number right before page data
				if (iAmt == 4) {
					page_number = LOAD_32_BE(p);
				}
				break;

			case EncryptedFileType::Wal:
				// SQLite writes the page number in the WAL frame header right before writing page data
				if (ioop == IoOp::Write) {
					if (iAmt == SQLITE_FORMAT_WAL_HEADER_SIZE) {
						page_number = LOAD_32_BE(p);
					}
				}
				// SQLite reads page data without necessarily reading the WAL frame header, so we must manually read it at all times
				else {
					RETURN_IF_NOT_OK(SQLiteFileImpl::xRead(&page_number, 4, iOfst - SQLITE_FORMAT_WAL_HEADER_SIZE));
					page_number = LOAD_32_BE(&page_number);
				}
				break;

			default:
				break;
        }
		return SQLITE_OK;
	}
};

struct CryptoVfs : public SQLiteVfsImpl<EncryptedFile> {
	int xOpen(sqlite3_filename zName, SQLiteFile<EncryptedFile> *file, int flags, int *pOutFlags) override {
		int result = SQLiteVfsImpl::xOpen(zName, file, flags, pOutFlags);
		if (result == SQLITE_OK) {
			file->implementation.setup(zName, flags);
		}
		return result;
	}
};


/**
 * Auto extension to run on new databases: if creating the database (its size is 0),
 * reserve a default amount of bytes for storing the encryption nonce and authentication tag.
 */
int auto_extension(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
	SQLITE_EXTENSION_INIT2(pApi);

	sqlite3_vfs *vfs = nullptr;
	sqlite3_file_control(db, nullptr, SQLITE_FCNTL_VFS_POINTER, &vfs);
	if (vfs && strcmp(vfs->zName, CRYPTOVFS_NAME) == 0) {
		sqlite3_file *file = nullptr;
		sqlite3_int64 file_size;
		sqlite3_file_control(db, nullptr, SQLITE_FCNTL_FILE_POINTER, &file);
		if (file && file->pMethods->xFileSize(file, &file_size) == SQLITE_OK && file_size == 0) {
			int reserved_bytes = CRYPTOVFS_DEFAULT_RESERVED_BYTES;
			sqlite3_file_control(db, nullptr, SQLITE_FCNTL_RESERVE_BYTES, &reserved_bytes);
		}
	}

	return SQLITE_OK;
}

}

extern "C" {

int cryptovfs_register(int makeDefault) {
	if (sodium_init() < 0) {
		return CRYPTOVFS_LIBSODIUM_INIT_ERROR;
	}

	sqlite3_auto_extension((void (*)(void)) cryptovfs::auto_extension);

	static SQLiteVfs<cryptovfs::CryptoVfs> cryptovfs(CRYPTOVFS_NAME);
	return cryptovfs.register_vfs(makeDefault);
}

/*
** This routine is called when the extension is loaded.
** Register the new VFS.
*/
int sqlite3_cryptovfs_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
	SQLITE_EXTENSION_INIT2(pApi);

	int rc = cryptovfs_register(0);
	if (rc == SQLITE_OK) {
		rc = SQLITE_OK_LOAD_PERMANENTLY;
	}
	return rc;
}

}
