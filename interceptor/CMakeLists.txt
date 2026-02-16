find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

add_library(interceptor STATIC 
    fuse.cpp 
    fuse.hpp 
    interceptor.hpp
)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../subjectInfo" "${CMAKE_CURRENT_BINARY_DIR}/subjectInfo")

target_link_libraries(interceptor 
    PRIVATE
    PkgConfig::FUSE3
    subjectInfo
)

target_include_directories(interceptor
    INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_include_directories(interceptor
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../spdlog/include"
)
