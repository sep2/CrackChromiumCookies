cmake_minimum_required(VERSION 3.0)
project(CrackChromiumCookies)

set(CMAKE_EXPORT_COMPILE_COMMANDS on)

set(executable_name ${PROJECT_NAME})
set(src_directory src)
set(include_directory include)
set(test_directory test)

file(GLOB_RECURSE src_files ${src_directory}/*.cpp ${src_directory}/*.h)
file(GLOB_RECURSE header_files ${include_directory}/*.h)
file(GLOB_RECURSE test_files ${test_directory}/*.cpp)

add_executable(${executable_name} ${src_files})

target_compile_options(${executable_name} PUBLIC -std=c++17 -Wall -Wfloat-conversion)

target_include_directories(${executable_name} PUBLIC
    ${src_directory}
    ${include_directory}
    /usr/include/glib-2.0
    /usr/lib/glib-2.0/include
    /usr/include/libsecret-1
)

target_link_libraries(${executable_name} PUBLIC
    crypto
    glib-2.0
    secret-1
    sqlite3
)

