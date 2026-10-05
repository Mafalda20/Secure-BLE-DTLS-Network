cmake_minimum_required(VERSION 3.21)

project(sink_advertising_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)

pkg_check_modules(
    GIO
    REQUIRED
    IMPORTED_TARGET
    gio-2.0
)

add_executable(
    sic_sink
    src/main.cpp
    ../common/link_security.cpp
)

target_link_libraries(
    sic_sink
    PRIVATE
    PkgConfig::GIO
)

target_include_directories(sic_sink PRIVATE ../common)
