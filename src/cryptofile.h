#include <sqlite3.h>

typedef struct encrypted_file {
	sqlite3_file base;
	sqlite3_file original_file[0];
} encrypted_file;

#define ORIGFILE(p)  (((encrypted_file *) (p))->original_file)

void cryptovfs_fill_io_methods(encrypted_file *file);