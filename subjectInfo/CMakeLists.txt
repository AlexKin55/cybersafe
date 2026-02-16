find_library(UUID_LIB uuid REQUIRED)

add_library(subjectInfo STATIC 
    subjectInfo.cpp 
    subjectInfo.hpp 
)

target_link_libraries(subjectInfo PRIVATE ${UUID_LIB})
target_include_directories(subjectInfo INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

