set(LIB_NAME claude_crypto)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        aead.hpp
        asymmetric.hpp
        crypto_error.hpp
        crypto_provider.hpp
        defs.hpp
        digests.hpp
        ecc.hpp
        ecdh.hpp
        kdf.hpp
        mac.hpp
        psa_backend.hpp
        provider.hpp
        random.hpp
        secure_buffer.hpp
        sha_variant.hpp
        sigma.hpp
        sigma_i.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
