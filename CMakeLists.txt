cmake_minimum_required(VERSION 3.22)
project(dbus_util C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)


add_library(dbus_util src/dbus-util.c src/vec.c)

find_package(LibXml2 REQUIRED)
find_package(DBUS REQUIRED)

target_link_libraries(dbus_util PRIVATE ${DBUS_LIBRARIES} xml2)
target_include_directories(dbus_util PRIVATE ${DBUS_INCLUDE_DIRS} ${LIBXML2_INCLUDE_DIR})

target_include_directories(dbus_util PUBLIC include)

enable_testing()

add_subdirectory(test)