set(LIB_NAME claude_crypto)

add_library(${LIB_NAME} STATIC claude_crypto.cpp)

target_include_directories(${LIB_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
