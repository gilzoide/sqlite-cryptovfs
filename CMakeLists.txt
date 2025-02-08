cmake_minimum_required(VERSION 3.0)

project(sqlite3-cryptovfs C CXX)

option(CRYPTOVFS_BUILD_TEST "Whether test executable should be built" OFF)
option(CRYPTOVFS_ENABLE_ASAN "Whether to enable address sanitizer" OFF)
option(CRYPTOVFS_BUILD_SHARED_LIBS "Whether to build cryptovfs as a shared library" ${BUILD_SHARED_LIBS})

add_subdirectory(libs)

if (CRYPTOVFS_BUILD_SHARED_LIBS)
    set(CRYPTOVFS_LIBRARY_TYPE SHARED)
else ()
    set(CRYPTOVFS_LIBRARY_TYPE STATIC)
endif ()

add_library(cryptovfs
    ${CRYPTOVFS_LIBRARY_TYPE}
    "include/cryptovfs.h"
    "src/cryptovfs.cpp"
    "src/sqlite_memory.hpp"
    "src/sodium_memory.hpp"
    "src/utils.hpp"
)
target_compile_features(cryptovfs PRIVATE cxx_std_11)
target_include_directories(cryptovfs PUBLIC "include")
if (CRYPTOVFS_BUILD_SHARED_LIBS)
    target_link_libraries(cryptovfs sqlite3)
endif ()
target_link_libraries(cryptovfs libs)

if (CRYPTOVFS_ENABLE_ASAN)
    target_compile_options(cryptovfs PRIVATE "-fno-omit-frame-pointer" "-fsanitize=address")
    target_link_options(cryptovfs PRIVATE "-fno-omit-frame-pointer" "-fsanitize=address")
endif ()

if (CRYPTOVFS_BUILD_TEST)
    add_subdirectory(test)
endif ()
