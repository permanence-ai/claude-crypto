set(LIB_NAME safe_crypto_lib_ia_asm)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        ia_asm_backend.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
