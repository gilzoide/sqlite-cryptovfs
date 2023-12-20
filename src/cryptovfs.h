#ifndef __CRYPTOVFS_H__
#define __CRYPTOVFS_H__

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;
int sqlite3_cryptovfs_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);

#endif  // __CRYPTOVFS_H__