# Define the static library
add_library(interceptor STATIC 
    fuse.cpp 
    fuse.hpp 
    interceptor.hpp
)

# Link FUSE3 to the library (since fuse.cpp uses it)
target_link_libraries(interceptor PUBLIC ${FUSE3_LIBRARIES})

# Include FUSE3 directories
target_include_directories(interceptor PUBLIC ${FUSE3_INCLUDE_DIRS})

# Make sure anyone linking to this lib knows where the headers are
target_include_directories(interceptor INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
