set(LIB_NAME claude_crypto)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        aead.hpp
        asymmetric.hpp
        crypto_error.hpp
        defs.hpp
        digests.hpp
        ecc.hpp
        ecdh.hpp
        kdf.hpp
        mac.hpp
        random.hpp
        secure_buffer.hpp
        sigma.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${LIB_NAME} INTERFACE
        mbedtls
)
