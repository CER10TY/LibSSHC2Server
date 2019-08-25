cmake_minimum_required(VERSION 3.14)
project(LibSSHClient C)

set(CMAKE_C_STANDARD 99)

add_executable(LibSSHClient main.c)

find_package(libssh REQUIRED)
target_link_libraries(LibSSHClient PRIVATE ${LIBSSH_LIBRARIES})
target_include_directories(LibSSHClient PRIVATE ${LIBSSH_INCLUDE_DIRS})