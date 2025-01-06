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
#define SQLITE_FORMAT_HEADER_SIZE 100

// Helper macros for byte/math operations
#define LOAD_8(p) \
	(((uint8_t *) p)[0])
#define LOAD_16_BE(p) \
	(((uint8_t *) p)[0] << 8) + (((uint8_t *) p)[1])
#define MIN(a, b) \
	((a) < (b) ? (a) : (b))
#define MAX(a, b) \
	((a) > (b) ? (a) : (b))

#define STARTS_WITH(buffer, literal_string) \
	(memcmp((buffer), (literal_string), sizeof(literal_string) - 1) == 0)

#define CRYPTOVFS_KEY_BYTES \
	crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define CRYPTOVFS_RESERVED_BYTES \
	crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define CRYPTOVFS_SALT_BYTES \
	crypto_pwhash_SALTBYTES
#define CRYPTOVFS_HEADER_UNENCRYPTED_BYTES 24

static_assert(CRYPTOVFS_SALT_BYTES == sizeof(SQLITE_FORMAT_HEADER_STRING), "Salt has different byte size than SQLite format header string");

using namespace sqlitevfs;

namespace cryptovfs {

enum class EncryptedFileType {
	Db,
	Journal,
	Wal,
	Temp,
};

struct EncryptedFile : public SQLiteFileImpl {
	SodiumMemory<char> text_key = nullptr;
	SodiumMemory<unsigned char> key = nullptr;
	SQLiteMemory<unsigned char> salt = nullptr;
	SQLiteMemory<unsigned char> encryption_buffer = nullptr;
	SQLiteMemory<unsigned char> nonce_buffer = nullptr;
	int page_size = 0;
	int reserved_bytes = 0;
	EncryptedFileType file_type;
	EncryptedFile *main_db_file;

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
			set_text_key(textkey_uri);
		}
		if (const char *key_uri = sqlite3_uri_parameter(zName, "key")) {
			set_key(key_uri);
		}
		if (const char *hexkey_uri = sqlite3_uri_parameter(zName, "hexkey")) {
			set_hex_key(hexkey_uri);
		}
	}

	int xRead(void *p, int iAmt, sqlite3_int64 iOfst) override {
		int base_result = SQLiteFileImpl::xRead(p, iAmt, iOfst);
		if (base_result != SQLITE_OK || !main_db_file->is_encrypted()) {
			return base_result;
		}

		switch (file_type) {
			case EncryptedFileType::Db: {
				if (iOfst == 0) {
					read_first_page(p, iAmt);
				}
				assert(page_size > 0 && "FIXME: page size was not read yet");
				// make sure we read the whole page before decrypting
				if (iAmt != page_size) {
					assert(iOfst / page_size == 0 && "FIXME: SQLite is partially reading something that is not in the first page");
					encryption_buffer.resize_at_least(page_size);
					base_result = SQLiteFileImpl::xRead(encryption_buffer, page_size, 0);
					if (base_result != SQLITE_OK) {
						return base_result;
					}

					if (const void *data = decrypt_page(encryption_buffer, page_size, 0)) {
						memcpy(p, encryption_buffer.ptr() + iOfst, iAmt);
					}
					else {
						return SQLITE_IOERR_READ;
					}
				}
				else {
					if (const void *data = decrypt_page((const unsigned char *) p, iAmt, iOfst)) {
						memcpy(p, encryption_buffer.ptr(), iAmt);
					}
					else {
						return SQLITE_IOERR_READ;
					}
				}
				break;
			}

			case EncryptedFileType::Journal:
			case EncryptedFileType::Wal:
				if (iAmt == main_db_file->page_size) {
					if (const void *data = decrypt_page((const unsigned char *) p, iAmt, iOfst)) {
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

		// The first page is special, as it stores the SQLite header and salt

		return SQLITE_OK;
	}

	int xWrite(const void *p, int iAmt, sqlite3_int64 iOfst) override {
		switch (file_type) {
			case EncryptedFileType::Db:
                // The first page is special, as it stores the SQLite header
				if (iOfst == 0) {
					read_first_page(p, iAmt);
				}
				if (is_encrypted()) {
					p = encrypt_page((unsigned char *) p, iAmt);
				}
				break;

			case EncryptedFileType::Journal:
			case EncryptedFileType::Wal:
				if (main_db_file->is_encrypted() && iAmt == main_db_file->page_size) {
					p = encrypt_page((unsigned char *) p, iAmt);
				}
				break;

			default:
				break;
		}

		if (p == nullptr) {
			return SQLITE_IOERR_WRITE;
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
		return key || text_key;
	}

	void set_text_key(const char *textkey) {
		text_key = SodiumMemory<char>(textkey, strlen(textkey) + 1);
	}

	void set_hex_key(const char *hexkey) {
		if (!key) {
			key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
		}
		size_t hexkey_length = strlen(hexkey);
		size_t binlen = 1;
		for (int i = 0; i < CRYPTOVFS_KEY_BYTES && binlen > 0; i += binlen) {
			sodium_hex2bin(key.ptr() + i, CRYPTOVFS_KEY_BYTES - i, hexkey, hexkey_length, ":", &binlen, NULL);
		}
	}

	void set_key(const char *newkey) {
		if (!key) {
			key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
		}
		size_t newkey_length = strlen(newkey);
		size_t batch_size;
		for (int i = 0; i < CRYPTOVFS_KEY_BYTES; i += batch_size) {
			batch_size = MIN(CRYPTOVFS_KEY_BYTES - i, newkey_length);
			memcpy(key.ptr() + i, newkey, batch_size);
		}
	}

	void read_first_page(const void *p, int size) {
		if (size >= SQLITE_FORMAT_HEADER_SIZE) {
			page_size = LOAD_16_BE(p + SQLITE_FORMAT_PAGE_SIZE_OFFSET);
			if (page_size == 1) {
				page_size = 65536;
			}
			reserved_bytes = LOAD_8(p + SQLITE_FORMAT_RESERVED_BYTES_OFFSET);

			if (!STARTS_WITH(p, SQLITE_FORMAT_HEADER_STRING)) {
				salt = SQLiteMemory<unsigned char>((unsigned char *) p, CRYPTOVFS_SALT_BYTES);
			}
		}
	}

	const void *encrypt_page(const unsigned char *p, int iAmt) {
		encryption_buffer.resize_at_least(iAmt);
		int written_bytes = 0;
		// 1st page: store the salt in place of "SQLite format 3" and skip page size and reserved bytes
		if (STARTS_WITH(p, SQLITE_FORMAT_HEADER_STRING)) {
			memcpy(encryption_buffer.ptr(), get_or_generate_salt(), CRYPTOVFS_SALT_BYTES);
			memcpy(encryption_buffer.ptr() + CRYPTOVFS_SALT_BYTES, p + CRYPTOVFS_SALT_BYTES, CRYPTOVFS_HEADER_UNENCRYPTED_BYTES - CRYPTOVFS_SALT_BYTES);
			written_bytes = CRYPTOVFS_HEADER_UNENCRYPTED_BYTES;
		}

		int reserved_bytes = main_db_file->reserved_bytes;
		if (reserved_bytes >= 40) {
			unsigned char *nonce = fill_nonce(p + iAmt - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, true);
			int result = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
				encryption_buffer.ptr() + written_bytes,
				encryption_buffer.ptr() + iAmt - 40, nullptr,
				p + written_bytes, iAmt - written_bytes - reserved_bytes,
				nullptr, 0,
				nullptr,
				nonce,
				main_db_file->get_or_derive_key()
			);
			if (result != 0) {
				return nullptr;
			}
			// write nonce into buffer
			memcpy(encryption_buffer.ptr() + iAmt - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
		}
		return encryption_buffer;
	}

	const void *decrypt_page(const unsigned char *encrypted_page, int iAmt, sqlite3_int64 iOfst) {
		encryption_buffer.resize_at_least(iAmt);

		int written_bytes = 0;
		if (iOfst == 0) {
			memcpy(encryption_buffer.ptr(), SQLITE_FORMAT_HEADER_STRING, sizeof(SQLITE_FORMAT_HEADER_STRING));
			memcpy(encryption_buffer.ptr() + sizeof(SQLITE_FORMAT_HEADER_STRING), encrypted_page + sizeof(SQLITE_FORMAT_HEADER_STRING), CRYPTOVFS_HEADER_UNENCRYPTED_BYTES - sizeof(SQLITE_FORMAT_HEADER_STRING));
			written_bytes = CRYPTOVFS_HEADER_UNENCRYPTED_BYTES;
		}

		int reserved_bytes = main_db_file->reserved_bytes;
		if (reserved_bytes >= 40) {
			unsigned char *nonce = fill_nonce(encrypted_page + iAmt - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, false);
			int result = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
				encryption_buffer.ptr() + written_bytes,
				nullptr,
				encrypted_page + written_bytes, iAmt - written_bytes - reserved_bytes,
				encrypted_page + iAmt - 40,
				nullptr, 0,
				nonce,
				main_db_file->get_or_derive_key()
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
		nonce_buffer.resize_at_least(nonce_size);
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
		return nonce_buffer;
	}

	unsigned char *get_or_derive_key() {
		if (!key && text_key) {
			key = SodiumMemory<unsigned char>((size_t) CRYPTOVFS_KEY_BYTES);
			int result = crypto_pwhash(
				key, CRYPTOVFS_KEY_BYTES,
				text_key, text_key.size(),
				salt,
				crypto_pwhash_OPSLIMIT_MODERATE,
				crypto_pwhash_MEMLIMIT_MODERATE,
				crypto_pwhash_ALG_DEFAULT
			);
			if (result != 0) {
				return nullptr;
			}
			text_key.free();
		}
		return key;
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

}

/*
** This routine is called when the extension is loaded.
** Register the new VFS.
*/
extern "C" {

int cryptovfs_register(int makeDefault) {
	if (sodium_init() < 0) {
		return -1;
	}

	static SQLiteVfs<cryptovfs::CryptoVfs> cryptovfs(CRYPTOVFS_NAME);
	return cryptovfs.register_vfs(makeDefault);
}

int sqlite3_cryptovfs_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
	SQLITE_EXTENSION_INIT2(pApi);

	int rc = cryptovfs_register(1);
	if (rc == SQLITE_OK) {
		rc = SQLITE_OK_LOAD_PERMANENTLY;
	}
	return rc;
}

}
