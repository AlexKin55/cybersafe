cmake_minimum_required(VERSION 3.20)
project(CybersafeAgent LANGUAGES CXX)

# Require C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find FUSE 3 (Required for both lib and exe)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

# Add the interceptor subdirectory
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../interceptor ${CMAKE_CURRENT_BINARY_DIR}/build)

# Define the Agent executable
add_executable(cybersafe_agent main.cpp)

# Link the static library and FUSE3
target_link_libraries(cybersafe_agent 
    PRIVATE 
    interceptor
    ${FUSE3_LIBRARIES}
)

# Ensure the executable can find headers from the library
target_include_directories(cybersafe_agent PRIVATE interceptor)
