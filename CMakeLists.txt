cmake_minimum_required(VERSION 3.0)

project(sqlite3-cryptovfs CXX)

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

add_library(cryptovfs src/cryptovfs.cpp src/cryptovfs.h)
target_compile_features(cryptovfs PRIVATE cxx_std_11)
target_include_directories(cryptovfs PRIVATE libs/sqlite-vfs-cpp "${CMAKE_CURRENT_BINARY_DIR}/include")
target_link_libraries(cryptovfs "${CMAKE_CURRENT_BINARY_DIR}/lib/libsodium.a")
add_dependencies(cryptovfs libsodium)