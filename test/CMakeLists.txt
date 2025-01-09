add_executable(cryptovfs_test "main.c" "sqlite3.c")
set_source_files_properties("sqlite3.c"
    PROPERTIES COMPILE_FLAGS
    "-O3 \
        -DSQLITE_USE_URI \
        -DSQLITE_DQS=0 \
        -DSQLITE_DEFAULT_MEMSTATUS=0 \
        -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1 \
        -DSQLITE_LIKE_DOESNT_MATCH_BLOBS \
        -DSQLITE_MAX_EXPR_DEPTH=0 \
        -DSQLITE_OMIT_DECLTYPE \
        -DSQLITE_OMIT_DEPRECATED \
        -DSQLITE_OMIT_PROGRESS_CALLBACK \
        -DSQLITE_OMIT_SHARED_CACHE \
        -DSQLITE_USE_ALLOCA \
        -DHAVE_ISNAN \
    "
)
if (CRYPTOVFS_ENABLE_ASAN)
    target_compile_options(cryptovfs_test PRIVATE "-fno-omit-frame-pointer" "-fsanitize=address")
    target_link_options(cryptovfs_test PRIVATE "-fno-omit-frame-pointer" "-fsanitize=address")
endif ()
target_link_libraries(cryptovfs_test cryptovfs)
