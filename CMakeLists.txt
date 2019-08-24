cmake_minimum_required(VERSION 3.14)
project(libsshserver C)

set(CMAKE_C_STANDARD 99)

add_executable(libsshserver main.c)

find_package(libssh REQUIRED)
target_link_libraries(libsshserver PRIVATE ${LIBSSH_LIBRARIES})
target_include_directories(libsshserver PRIVATE ${LIBSSH_INCLUDE_DIRS})