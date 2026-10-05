cmake_minimum_required(VERSION 3.21)

project(uplink_connect_test)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)

pkg_check_modules(SIMPLEBLE REQUIRED simpleble)
pkg_check_modules(DBUS REQUIRED dbus-1)
pkg_check_modules(GIO REQUIRED gio-2.0)

add_executable(
    sic_node
    src/main.cpp
    ../common/link_security.cpp
)

target_include_directories(
    sic_node
    PRIVATE
    ${SIMPLEBLE_INCLUDE_DIRS}
    ${DBUS_INCLUDE_DIRS}
    ${GIO_INCLUDE_DIRS}
    ../common
)

target_link_directories(
    sic_node
    PRIVATE
    ${SIMPLEBLE_LIBRARY_DIRS}
    ${DBUS_LIBRARY_DIRS}
    ${GIO_LIBRARY_DIRS}
)

target_link_libraries(
    sic_node
    PRIVATE
    ${SIMPLEBLE_LIBRARIES}
    ${DBUS_LIBRARIES}
    ${GIO_LIBRARIES}
)
