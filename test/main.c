#include <stdio.h>
#include <stdlib.h>

#include <cryptovfs.h>

#include "sqlite3.h"

int sql_callback(void *userdata, int column_count, char **column_values, char **column_names) {
	printf("|");
	for (int i = 0; i < column_count; i++) {
		printf("%s", column_values[i]);
		printf("|");
	}
	printf("\n");
	return SQLITE_OK;
}

void run_sql(sqlite3 *db, const char *sql) {
	char *errmsg;
	printf("> %s\n", sql);
	sqlite3_exec(db, sql, sql_callback, NULL, &errmsg);
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

	run_sql(db, "PRAGMA textkey = '012345'");
	run_sql(db, "PRAGMA journal_mode = 'wal'");
	run_sql(db, "BEGIN");
	run_sql(db, "CREATE TABLE IF NOT EXISTS test(col1, col2)");
	run_sql(db, "INSERT INTO test DEFAULT VALUES returning rowid");
	run_sql(db, "COMMIT");

	sqlite3_close(db);
	return 0;
}
