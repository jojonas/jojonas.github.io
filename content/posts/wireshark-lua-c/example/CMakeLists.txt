cmake_minimum_required (VERSION 3.10)
project (lexample C)

find_package(Lua 5.2 EXACT REQUIRED)

include_directories (
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LUA_INCLUDE_DIR}
)

set (SOURCES lexample.c)

add_library (${PROJECT_NAME} SHARED ${SOURCES} ${LUA_LIBRARIES})
target_link_libraries (${PROJECT_NAME})
set_target_properties (${PROJECT_NAME} PROPERTIES PREFIX "")