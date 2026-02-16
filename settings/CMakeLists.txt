
add_library(settings STATIC 
    settings.cpp 
    settings.hpp 
)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../yaml-cpp" "${CMAKE_CURRENT_BINARY_DIR}/yaml-cpp")

target_link_libraries(settings PRIVATE yaml-cpp)
target_include_directories(settings INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
