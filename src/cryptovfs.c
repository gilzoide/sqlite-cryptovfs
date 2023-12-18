#include <stdlib.h>
#include <sqlite3.h>
#include <sqlite3ext.h>

#include "cryptofile.h"
#include "cryptovfs.h"


static int cryptoOpen(sqlite3_vfs *vfs, const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags) {
	int rc = ORIGVFS(vfs)->xOpen(ORIGVFS(vfs), zName, ORIGFILE(pFile), flags, pOutFlags);
	cryptovfs_fill_io_methods((encrypted_file *) pFile);
	return rc;
}

/*
** All other VFS methods are pass-thrus.
*/
static int cryptoDelete(sqlite3_vfs *vfs, const char *zPath, int dirSync){
  return ORIGVFS(vfs)->xDelete(ORIGVFS(vfs), zPath, dirSync);
}
static int cryptoAccess(sqlite3_vfs *vfs, const char *zPath, int flags, int *pResOut) {
	return ORIGVFS(vfs)->xAccess(ORIGVFS(vfs), zPath, flags, pResOut);
}
static int cryptoFullPathname(sqlite3_vfs *vfs, const char *zPath, int nOut, char *zOut) {
	return ORIGVFS(vfs)->xFullPathname(ORIGVFS(vfs),zPath,nOut,zOut);
}
static void *cryptoDlOpen(sqlite3_vfs *vfs, const char *zPath) {
	return ORIGVFS(vfs)->xDlOpen(ORIGVFS(vfs), zPath);
}
static void cryptoDlError(sqlite3_vfs *vfs, int nByte, char *zErrMsg){
  ORIGVFS(vfs)->xDlError(ORIGVFS(vfs), nByte, zErrMsg);
}
static void (*cryptoDlSym(sqlite3_vfs *vfs, void *p, const char *zSym))(void) {
	return ORIGVFS(vfs)->xDlSym(ORIGVFS(vfs), p, zSym);
}
static void cryptoDlClose(sqlite3_vfs *vfs, void *pHandle){
  ORIGVFS(vfs)->xDlClose(ORIGVFS(vfs), pHandle);
}
static int cryptoRandomness(sqlite3_vfs *vfs, int nByte, char *zBufOut) {
	return ORIGVFS(vfs)->xRandomness(ORIGVFS(vfs), nByte, zBufOut);
}
static int cryptoSleep(sqlite3_vfs *vfs, int nMicro) {
	return ORIGVFS(vfs)->xSleep(ORIGVFS(vfs), nMicro);
}
static int cryptoCurrentTime(sqlite3_vfs *vfs, double *pTimeOut) {
	return ORIGVFS(vfs)->xCurrentTime(ORIGVFS(vfs), pTimeOut);
}
static int cryptoGetLastError(sqlite3_vfs *vfs, int a, char *b) {
	return ORIGVFS(vfs)->xGetLastError(ORIGVFS(vfs), a, b);
}
static int cryptoCurrentTimeInt64(sqlite3_vfs *vfs, sqlite3_int64 *p) {
	return ORIGVFS(vfs)->xCurrentTimeInt64(ORIGVFS(vfs), p);
}
static int cryptoSetSystemCall(sqlite3_vfs *vfs, const char *zName, sqlite3_syscall_ptr pCall) {
	return ORIGVFS(vfs)->xSetSystemCall(ORIGVFS(vfs),zName,pCall);
}
static sqlite3_syscall_ptr cryptoGetSystemCall(sqlite3_vfs *vfs, const char *zName) {
	return ORIGVFS(vfs)->xGetSystemCall(ORIGVFS(vfs),zName);
}
static const char *cryptoNextSystemCall(sqlite3_vfs *vfs, const char *zName) {
	return ORIGVFS(vfs)->xNextSystemCall(ORIGVFS(vfs), zName);
}

/* 
** This routine is called when the extension is loaded.
** Register the new VFS.
*/
int sqlite3_cryptovfs_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
	static sqlite3_vfs crypto_vfs = {
		3,                            /* iVersion (set when registered) */
		0,                            /* szOsFile (set when registered) */
		1024,                         /* mxPathname */
		0,                            /* pNext */
		"cryptovfs",                  /* zName */
		0,                            /* pAppData (set when registered) */ 
		cryptoOpen,                   /* xOpen */
		cryptoDelete,                 /* xDelete */
		cryptoAccess,                 /* xAccess */
		cryptoFullPathname,           /* xFullPathname */
		cryptoDlOpen,                 /* xDlOpen */
		cryptoDlError,                /* xDlError */
		cryptoDlSym,                  /* xDlSym */
		cryptoDlClose,                /* xDlClose */
		cryptoRandomness,             /* xRandomness */
		cryptoSleep,                  /* xSleep */
		cryptoCurrentTime,            /* xCurrentTime */
		cryptoGetLastError,           /* xGetLastError */
		cryptoCurrentTimeInt64,       /* xCurrentTimeInt64 */
		cryptoSetSystemCall,          /* xSetSystemCall */
		cryptoGetSystemCall,          /* xGetSystemCall */
		cryptoNextSystemCall,         /* xNextSystemCall */
	};

	SQLITE_EXTENSION_INIT2(pApi);
	sqlite3_vfs *pOrig = sqlite3_vfs_find(NULL);
	if (pOrig == NULL) {
		return SQLITE_ERROR;
	}
	crypto_vfs.iVersion = pOrig->iVersion;
	crypto_vfs.pAppData = pOrig;
	crypto_vfs.szOsFile = sizeof(encrypted_file) + pOrig->szOsFile;
	return sqlite3_vfs_register(&crypto_vfs, 0);
}