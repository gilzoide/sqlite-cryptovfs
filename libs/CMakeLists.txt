add_library(libs INTERFACE)

# Sodium
include(ExternalProject)
execute_process(
    COMMAND sh autogen.sh -s
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libsodium"
)
ExternalProject_Add(
    libsodium
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libsodium"
    CONFIGURE_COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure" "--prefix=${CMAKE_CURRENT_BINARY_DIR}"
    BUILD_COMMAND make
    COMMAND make install
)

target_include_directories(libs INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/include")
target_link_libraries(libs INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/lib/libsodium.a")
add_dependencies(libs libsodium)

# SQLiteVFS.hpp
target_include_directories(libs INTERFACE "sqlite-vfs-cpp")

