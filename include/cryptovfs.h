#ifndef __CRYPTOVFS_H__
#define __CRYPTOVFS_H__

#define CRYPTOVFS_NAME "cryptovfs"

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Registers cryptovfs in SQLite 3.
 *
 * @param makeDefault  Whether cryptovfs will be the new default VFS.
 * @return Return -1 if libsodium failed to initialize. Otherwise, retuns the value from `sqlite3_vfs_register`
 * @see https://sqlite.org/c3ref/vfs_find.html
 */
int cryptovfs_register(int makeDefault);

int sqlite3_cryptovfs_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);

#ifdef __cplusplus
}
#endif

#endif  // __CRYPTOVFS_H__
