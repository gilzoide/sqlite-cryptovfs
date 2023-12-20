#include <stdlib.h>
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

typedef struct encrypted_file {
	sqlite3_file base;
	sqlite3_file original_file[0];
} encrypted_file;

#define ORIGVFS(p)  ((sqlite3_vfs *) (p)->pAppData)
#define ORIGFILE(p)  (((encrypted_file *) (p))->original_file)

///////////////////////////////////////////////////////////
// File implementation
///////////////////////////////////////////////////////////
static int cryptoFileControl(sqlite3_file *pFile, int op, void *pArg) {
	switch (op) {
		case SQLITE_FCNTL_VFSNAME:
			*(char **) pArg = sqlite3_mprintf("%z", "cryptovfs");
			return SQLITE_OK;
		
		default:
			return ORIGFILE(pFile)->pMethods->xFileControl(ORIGFILE(pFile), op, pArg);
	}
}

// All other file methods are pass-thrus
static int cryptoClose(sqlite3_file *pFile) {
	return ORIGFILE(pFile)->pMethods->xClose(ORIGFILE(pFile));
}
static int cryptoRead(sqlite3_file *pFile, void *zBuf, int iAmt, sqlite_int64 iOfst) {
	return ORIGFILE(pFile)->pMethods->xRead(ORIGFILE(pFile), zBuf, iAmt, iOfst);
}
static int cryptoWrite(sqlite3_file *pFile, const void *zBuf, int iAmt, sqlite_int64 iOfst) {
	return ORIGFILE(pFile)->pMethods->xWrite(ORIGFILE(pFile), zBuf, iAmt, iOfst);
}
static int cryptoTruncate(sqlite3_file *pFile, sqlite_int64 size) {
	return ORIGFILE(pFile)->pMethods->xTruncate(ORIGFILE(pFile), size);
}
static int cryptoSync(sqlite3_file *pFile, int flags) {
	return ORIGFILE(pFile)->pMethods->xSync(ORIGFILE(pFile), flags);
}
static int cryptoFileSize(sqlite3_file *pFile, sqlite_int64 *pSize) {
	return ORIGFILE(pFile)->pMethods->xFileSize(ORIGFILE(pFile), pSize);
}
static int cryptoLock(sqlite3_file *pFile, int eLock) {
	return ORIGFILE(pFile)->pMethods->xLock(ORIGFILE(pFile), eLock);
}
static int cryptoUnlock(sqlite3_file *pFile, int eLock) {
	return ORIGFILE(pFile)->pMethods->xUnlock(ORIGFILE(pFile), eLock);
}
static int cryptoCheckReservedLock(sqlite3_file *pFile, int *pResOut) {
	return ORIGFILE(pFile)->pMethods->xCheckReservedLock(ORIGFILE(pFile), pResOut);
}
static int cryptoSectorSize(sqlite3_file *pFile) {
	return ORIGFILE(pFile)->pMethods->xSectorSize(ORIGFILE(pFile));
}
static int cryptoDeviceCharacteristics(sqlite3_file *pFile) {
	return ORIGFILE(pFile)->pMethods->xDeviceCharacteristics(ORIGFILE(pFile));
}
static int cryptoShmMap(sqlite3_file *pFile, int iPg, int pgsz, int bExtend, volatile void **pp) {
	return ORIGFILE(pFile)->pMethods->xShmMap(ORIGFILE(pFile), iPg, pgsz, bExtend, pp);
}
static int cryptoShmLock(sqlite3_file *pFile, int offset, int n, int flags) {
	return ORIGFILE(pFile)->pMethods->xShmLock(ORIGFILE(pFile), offset, n, flags);
}
static void cryptoShmBarrier(sqlite3_file *pFile) {
	ORIGFILE(pFile)->pMethods->xShmBarrier(ORIGFILE(pFile));
}
static int cryptoShmUnmap(sqlite3_file *pFile, int deleteFlag) {
	return ORIGFILE(pFile)->pMethods->xShmUnmap(ORIGFILE(pFile), deleteFlag);
}
static int cryptoFetch(sqlite3_file *pFile, sqlite3_int64 iOfst, int iAmt, void **pp) {
	return ORIGFILE(pFile)->pMethods->xFetch(ORIGFILE(pFile), iOfst, iAmt, pp);
}
static int cryptoUnfetch(sqlite3_file *pFile, sqlite3_int64 iOfst, void *pPage) {
	return ORIGFILE(pFile)->pMethods->xUnfetch(ORIGFILE(pFile), iOfst, pPage);
}


///////////////////////////////////////////////////////////
// VFS implementation
///////////////////////////////////////////////////////////
static int cryptoOpen(sqlite3_vfs *vfs, const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags) {
	int rc = ORIGVFS(vfs)->xOpen(ORIGVFS(vfs), zName, ORIGFILE(pFile), flags, pOutFlags);
	if (rc != SQLITE_OK) {
		return rc;
	}
	
	static sqlite3_io_methods io_methods = {
		3,                              /* iVersion */
		cryptoClose,                    /* xClose */
		cryptoRead,                     /* xRead */
		cryptoWrite,                    /* xWrite */
		cryptoTruncate,                 /* xTruncate */
		cryptoSync,                     /* xSync */
		cryptoFileSize,                 /* xFileSize */
		cryptoLock,                     /* xLock */
		cryptoUnlock,                   /* xUnlock */
		cryptoCheckReservedLock,        /* xCheckReservedLock */
		cryptoFileControl,              /* xFileControl */
		cryptoSectorSize,               /* xSectorSize */
		cryptoDeviceCharacteristics,    /* xDeviceCharacteristics */
		cryptoShmMap,                   /* xShmMap */
		cryptoShmLock,                  /* xShmLock */
		cryptoShmBarrier,               /* xShmBarrier */
		cryptoShmUnmap,                 /* xShmUnmap */
		cryptoFetch,                    /* xFetch */
		cryptoUnfetch,                  /* xUnfetch */
	};
	encrypted_file *file = (encrypted_file *) pFile;
	io_methods.iVersion = ORIGFILE(file)->pMethods->iVersion;
	file->base.pMethods = &io_methods;
	
	return rc;
}

// All other file methods are pass-thrus
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
	int rc = sqlite3_vfs_register(&crypto_vfs, 1);
	if (rc == SQLITE_OK) {
		rc = SQLITE_OK_LOAD_PERMANENTLY;
	}
	return rc;
}