
add_library(cryptor STATIC 
    AesCrt.cpp 
    AesCrt.hpp 
    icryptor.hpp
    keyGetterFromFile.hpp
    keyGetterFromFile.cpp
)

find_package(OpenSSL REQUIRED)

target_link_libraries(cryptor PUBLIC OpenSSL::Crypto)
target_include_directories(cryptor PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../subjectInfo")
target_include_directories(cryptor INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
