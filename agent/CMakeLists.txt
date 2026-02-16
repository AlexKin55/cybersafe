cmake_minimum_required(VERSION 3.20)
project(CybersafeAgent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../interceptor" "${CMAKE_CURRENT_BINARY_DIR}/interceptor")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../cryptor" "${CMAKE_CURRENT_BINARY_DIR}/cryptor")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../settings" "${CMAKE_CURRENT_BINARY_DIR}/settings")
#add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../spdlog" "${CMAKE_CURRENT_BINARY_DIR}/spdlog")
add_executable(cybersafe_agent main.cpp)

target_link_libraries(cybersafe_agent 
    PRIVATE
    interceptor
    cryptor
    settings
)

target_include_directories(cybersafe_agent
    PRIVATE
    interceptor
    cryptor
    settings
    "${CMAKE_CURRENT_SOURCE_DIR}/../subjectInfo"
    "${CMAKE_CURRENT_SOURCE_DIR}/../spdlog/include"
)
