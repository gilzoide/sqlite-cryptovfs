#include <stdio.h>
#include <stdlib.h>

#include <cryptovfs.h>

#include "sqlite3.h"

void run_sql(sqlite3 *db, const char *sql) {
	char *errmsg;
	sqlite3_exec(db, sql, NULL, NULL, &errmsg);
	if (errmsg) {
		printf("Error: %s\n  at %s\n", errmsg, sql);
		sqlite3_free(errmsg);
		abort();
	}
}

int main(int argc, const char **argv) {
	const char *database_name = argc > 1 ? argv[1] : "cryptovfs-test.db";

	sqlite3_cryptovfs_init(NULL, NULL, NULL);

	sqlite3 *db;
	if (sqlite3_open_v2(database_name, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, CRYPTOVFS_NAME) != SQLITE_OK) {
		printf("Could not open database %s: %s\n", database_name, sqlite3_errmsg(db));
		return 1;
	}

	int reserved_bytes = 40;
	sqlite3_file_control(db, "main", SQLITE_FCNTL_RESERVE_BYTES, &reserved_bytes);
	run_sql(db, "PRAGMA textkey = '012345'");
	run_sql(db, "CREATE TABLE IF NOT EXISTS test(col1, col2)");

	sqlite3_close(db);
	return 0;
}
