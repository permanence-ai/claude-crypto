# safe-crypto-lib

A modern C++26 cryptography library built on the PSA Crypto API (via MbedTLS 4.1). All operations return `std::expected` — no exceptions, no output parameters. Secrets are held in `SecureBuffer` / `FixedSecureBuffer` types that scrub memory on destruction.

## Features

| Area | API |
|---|---|
| Digests | SHA-256/384/512, SHA3-256/384/512 |
| MAC | HMAC (any SHA variant) |
| AEAD | AES-256-GCM, ChaCha20-Poly1305 |
| Asymmetric encryption | RSA-OAEP (3072, 4096-bit) |
| Signatures | ECDSA P-256/384/521, RSA-PSS (3072, 4096-bit) |
| Key agreement | ECDH P-256/384/521 |
| Key derivation | HKDF, HKDF-Expand (SHA-384) |
| Key exchange protocols | SIGMA, SIGMA-I (identity-hiding) |
| Random | Cryptographically secure random bytes |

## Design

**Provider abstraction.** All crypto operations are templated on a `CryptoProvider` concept. The default provider (`RealPsaBackend`) forwards to PSA/MbedTLS. A second provider (`IaAsmBackend`) stub is included as a starting point for an assembly implementation. Tests use `MockPsaBackend` (GMock) to exercise every error path without inducing real PSA failures.

**No PSA types in library headers.** The `safe-crypto-lib` INTERFACE target has zero dependency on MbedTLS headers. PSA-specific code lives entirely in `providers/psa_mbedtls/`. Swapping or adding a provider requires no changes to the library headers.

**Memory safety.** `SecureBuffer` (heap) and `FixedSecureBuffer<N>` (stack) call `mbedtls_platform_zeroize` on destruction. All key material flows through these types and through `PsaKeyHandle<Provider>`, an RAII wrapper that calls `destroy_key` on every exit path.

## Directory layout

```
safe-crypto-lib/          # INTERFACE library — headers only, no PSA dependency
providers/
  psa_mbedtls/            # INTERFACE library — RealPsaBackend, links mbedtls
  ia_asm/                 # INTERFACE library stub — IaAsmBackend skeleton
safe-crypto-lib-test/     # GoogleTest suite + MockPsaBackend
cmake/                    # FetchContent modules for MbedTLS and GoogleTest
```

## Build

```bash
# Configure
cmake -G Ninja -B cmake-build-debug -S .

# Build
cmake --build cmake-build-debug

# Test
./cmake-build-debug/safe-crypto-lib-test/safe_crypto_lib_test
```

For a release build, substitute `cmake-build-release` and add `-DCMAKE_BUILD_TYPE=Release`.

To select the IA ASM provider instead of PSA/MbedTLS, link `safe_crypto_lib_ia_asm` and pass `-DCLAUDE_CRYPTO_PROVIDER_IA_ASM` to the compiler.

## Stack

- **Language:** C++26
- **Build system:** CMake 3.31 + Ninja
- **Crypto backend:** MbedTLS 4.1.0 (PSA Crypto API, via FetchContent)
- **Test framework:** GoogleTest + GMock (via FetchContent)
