#include "cryptofile.h"

static int cryptoFileControl(sqlite3_file *pFile, int op, void *pArg) {
	switch (op) {
		case SQLITE_FCNTL_VFSNAME:
			*(char **) pArg = sqlite3_mprintf("%z", "cryptovfs");
			return SQLITE_OK;
		
		default:
			return ORIGFILE(pFile)->pMethods->xFileControl(ORIGFILE(pFile), op, pArg);
	}
}

/*
** All other file methods are pass-thrus.
*/
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

void cryptovfs_fill_io_methods(encrypted_file *file) {
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

	io_methods.iVersion = ORIGFILE(file)->pMethods->iVersion;
	file->base.pMethods = &io_methods;
}