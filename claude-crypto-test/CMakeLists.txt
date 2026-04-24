set(EXE_NAME claude_crypto_test)

add_executable(${EXE_NAME} main.cpp)

target_link_libraries(${EXE_NAME} PRIVATE claude_crypto)
