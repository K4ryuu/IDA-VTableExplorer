cmake_minimum_required(VERSION 3.20)
project(VTableExplorer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IDASDK_DIR "" CACHE PATH "Path to IDA SDK root (containing include/ and lib/)")

if(NOT IDASDK_DIR)
    message(FATAL_ERROR "IDASDK_DIR must be set. Example: -DIDASDK_DIR=C:/idasdk")
endif()

if(NOT EXISTS "${IDASDK_DIR}/include/ida.hpp")
    message(FATAL_ERROR "IDASDK_DIR does not point to a valid IDA SDK: ${IDASDK_DIR}")
endif()

add_library(vtable64 SHARED src/main.cpp)

target_include_directories(vtable64 PRIVATE "${IDASDK_DIR}/include")

target_compile_definitions(vtable64 PRIVATE
    __NT__
    __EA64__
    __X64__
)

if(MSVC)
    target_compile_options(vtable64 PRIVATE /EHsc /W3)
endif()

target_link_libraries(vtable64 PRIVATE "${IDASDK_DIR}/lib/x64_win_vc_64/ida.lib")

set_target_properties(vtable64 PROPERTIES
    OUTPUT_NAME "vtable64"
    SUFFIX ".dll"
    PREFIX ""
)
