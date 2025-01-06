cmake_minimum_required(VERSION 3.0)

project(sqlite3-cryptovfs C CXX)

option(CRYPTOVFS_BUILD_TEST "Whether test executable should be built" OFF)
option(BUILD_SHARED_LIBS "Whether to build shared library" OFF)

include(ExternalProject)
execute_process(
    COMMAND sh autogen.sh -s
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/libs/libsodium"
)
ExternalProject_Add(
    libsodium
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/libs/libsodium"
    CONFIGURE_COMMAND "${CMAKE_SOURCE_DIR}/libs/libsodium/configure" "--prefix=${CMAKE_CURRENT_BINARY_DIR}"
    BUILD_COMMAND make
    COMMAND make install
)

add_library(cryptovfs
    "include/cryptovfs.h"
    "src/cryptovfs.cpp"
    "src/sqlite_memory.hpp"
    "src/sodium_memory.hpp"
    "src/utils.hpp"
)
target_compile_features(cryptovfs PRIVATE cxx_std_11)
target_include_directories(cryptovfs
    PUBLIC "include"
    PRIVATE "libs/sqlite-vfs-cpp" "${CMAKE_CURRENT_BINARY_DIR}/include"
)
target_link_libraries(cryptovfs "${CMAKE_CURRENT_BINARY_DIR}/lib/libsodium.a")
if (BUILD_SHARED_LIBS)
    target_link_libraries(cryptovfs sqlite3)
endif ()
add_dependencies(cryptovfs libsodium)

if (CRYPTOVFS_BUILD_TEST)
    add_subdirectory(test)
endif ()
