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

### Error handling — `std::expected<T, CryptoError>`

Every function that can fail returns `std::expected<T, CryptoError>` — no exceptions, no output parameters, no boolean return codes. The error type carries a typed `CryptoErrorCode` and a human-readable message string.

Callers use the monadic interface (`value_or`, `and_then`, `transform`, `or_else`) or simple `has_value()` / `.error()` checks. There is nothing to catch and no way to silently discard a failure: the `[[nodiscard]]` attribute is applied to every returning function, so ignoring a result is a compile-time warning.

The distinction between the two failure channels is deliberate:
- **`std::unexpected(CryptoError(...))`** — a recoverable runtime condition: a PSA operation failed, a signature didn't verify, wire data was malformed. The caller is expected to handle or propagate these.
- **`SAFE_CRYPTO_PRE(cond)` contract** — a programming error: passing zero as `output_length`, indexing past the end of a buffer, calling `get()` on a moved-from key handle. These are bugs in the caller, not conditions to recover from.

### Precondition contracts — `SAFE_CRYPTO_PRE`

`contracts.hpp` defines a `SAFE_CRYPTO_PRE(cond)` macro that expands to the C++26 `[[pre: cond]]` attribute on GCC 15+ (compiled with `-fcontracts`) and to a no-op on other compilers. The macro is placed between the cv/ref qualifiers and the trailing return type:

```cpp
auto operator[](std::size_t i) SAFE_CRYPTO_PRE(i < data_.size()) -> CryptoByte&;
auto get() const noexcept SAFE_CRYPTO_PRE(valid_) -> KeyId;
```

Contracts are used at all points where a violated precondition indicates a bug rather than a runtime condition:

| Location | Precondition |
|---|---|
| `SecureBuffer::operator[]` | `i < data_.size()` |
| `FixedSecureBuffer::operator[]` | `i < N` |
| `SecureBuffer::resize` | `new_size <= data_.size()` (shrink-only) |
| `PsaKeyHandle::get()` | handle is valid (not moved-from) |
| `sigma_i_serialize_bundle` | both length fields fit in `uint16_t` |
| `derive_key_impl`, `expand_key_impl` | `output_length > 0` |
| `random_bytes_impl` | `length > 0` |

The companion macro `SAFE_CRYPTO_CONTRACTS_ENFORCED` is defined when contracts produce runtime checks. Test death-assertions are gated on this macro so they only run on compilers that actually enforce contracts.

### Provider abstraction — `CryptoProvider` concept

All crypto operations are templated on a `CryptoProvider` concept defined in `crypto_provider.hpp`. The concept requires associated types (`Status`, `KeyId`, `Algorithm`, `KeyAttributes`, `KdfOperation`, `KdfStep`), status sentinels, object factories, algorithm constants, and all low-level crypto primitives.

The default provider (`RealPsaBackend`) forwards to PSA/MbedTLS. A second provider (`ArmAsmBackend`) implements hashing and HMAC directly via ARM Crypto Extension intrinsics — see [ARM ASM provider](#arm-asm-provider) below. Tests use `MockPsaBackend` (GMock) to exercise every error path without inducing real PSA failures.

### No PSA types in library headers

The `safe-crypto-lib` INTERFACE target has zero dependency on MbedTLS headers. PSA-specific code lives entirely in `providers/psa_mbedtls/`. Swapping or adding a provider requires no changes to the library headers or any `_impl` function body.

### Memory safety — `SecureBuffer` and `PsaKeyHandle`

`SecureBuffer` (heap) and `FixedSecureBuffer<N>` (stack) zeroize their contents on destruction using a volatile byte loop that the compiler cannot optimize away. All key material, derived secrets, and intermediate buffers flow through these types — there is no `std::vector<uint8_t>` holding sensitive data anywhere in the library.

`PsaKeyHandle<Provider>` is an RAII wrapper around a PSA key ID. It calls `destroy_key` in its destructor and on every move-assignment path, ensuring that imported and generated keys are destroyed even when an error is returned mid-function. `get()` carries a precondition that the handle is valid, making use-after-move a detectable bug rather than silent UB.

### ARM ASM provider

`providers/arm_asm/` is a header-only provider targeting ARMv8.2-A+crypto+sha3 (Apple Silicon M1 and later). It uses ARM Crypto Extension intrinsics directly — no MbedTLS dependency — compiled with `-march=armv8.2-a+crypto+sha3`.

**Implemented operations:**

| Operation | Notes |
|---|---|
| SHA-256 | `vsha256h_u32` / `vsha256h2_u32` compression intrinsics; full padding |
| SHA-384 | `vsha512hq_u64` / `vsha512h2q_u64` with SHA-384 initial state; first 48 bytes of output |
| SHA-512 | Same compression function, SHA-512 initial state; 64-byte output |
| HMAC-SHA-256 | Incremental `Sha256Ctx`; key hashing when key > 64 bytes |
| HMAC-SHA-384 | Incremental `Sha512Ctx` initialised with SHA-384 H₀; key hashing uses SHA-384 |
| HMAC-SHA-512 | Incremental `Sha512Ctx` initialised with SHA-512 H₀ |
| AES-256-GCM encrypt | AES-256 key expansion + CTR via `vaeseq_u8`/`vaesmcq_u8`; GHASH via `vmull_p64` PMULL; NIST SP 800-38D compliant |
| AES-256-GCM decrypt | Tag verification (constant-time compare) before decryption; output zeroized on auth failure |
| Random bytes | `arc4random_buf` — OS CSPRNG, never blocks |
| `generate_key` | Generates a random symmetric key of the size specified in `KeyAttributes` |
| `import_key` / `export_key` / `destroy_key` | Full implementation backed by the key store; keys zeroized on destroy |
| `mac_compute` / `mac_verify` | HMAC dispatch; `mac_verify` uses a constant-time compare |
| HKDF (SHA-384) | RFC 5869 Extract+Expand; full KDF state machine (`setup`/`input_key`/`input_bytes`/`output_bytes`/`abort`) |
| HKDF-Expand (SHA-384) | Expand-only variant; PRK supplied directly via `input_key` |
| Key store | 16-slot static store (up to 512 bytes/key) |
| ChaCha20-Poly1305 encrypt | NEON `uint32x4_t` quarter-round; Poly1305 over AAD‖CT‖lengths; RFC 8439 compliant |
| ChaCha20-Poly1305 decrypt | Tag verification (constant-time compare) before decryption; output zeroized on auth failure |

**Not yet implemented** (return `err_invalid_arg`): ECDSA/ECDH, RSA.

**SHA-512 compression loop detail.** The two-round step pattern cycles through four roles (ab/cd/ef/gh) every eight rounds. Each step requires cross-pair word interleaving that cannot be expressed as a simple state rotation:

```cpp
// Rounds 0,1 — targets gh, updates cd
initial_sum = vaddq_u64(s0, vld1q_u64(sha512_k));
sum         = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
intermed    = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
gh          = vsha512h2q_u64(intermed, cd, ab);
cd          = vaddq_u64(cd, intermed);
```

Rounds 16–79 interleave message schedule (`vsha512su0q_u64` / `vsha512su1q_u64`) with compression, processing eight word pairs per loop iteration.

## Directory layout

```
safe-crypto-lib/          # INTERFACE library — headers only, no PSA dependency
providers/
  psa_mbedtls/            # INTERFACE library — RealPsaBackend, links MbedTLS
  arm_asm/                # INTERFACE library — ArmAsmBackend, ARM intrinsics
  ia_asm/                 # INTERFACE library stub — skeleton only
safe-crypto-lib-test/     # GoogleTest suite + MockPsaBackend (229 tests)
cmake/                    # FetchContent modules for MbedTLS and GoogleTest
```

## Build

```bash
# Configure (PSA/MbedTLS provider is the default)
cmake -G Ninja -B cmake-build-debug -S .

# Build
cmake --build cmake-build-debug

# Test
./cmake-build-debug/safe-crypto-lib-test/safe_crypto_lib_test
```

For a release build, substitute `cmake-build-release` and add `-DCMAKE_BUILD_TYPE=Release`.

## Provider selection

The active backend is controlled by the `SAFE_CRYPTO_ACTIVE_PROVIDER` CMake cache variable. Pass it at configure time — CMake propagates the correct provider library and compile definitions to every target that links `safe_crypto_lib`, so no manual link step or compile flag is needed.

| Value | Backend | Status |
|---|---|---|
| `PSA_MBEDTLS` *(default)* | MbedTLS 4.1 PSA Crypto API | Production |
| `ARM_ASM` | ARMv8.2-A+crypto intrinsics (Apple Silicon) | Partial — hashing, HMAC, AES-256-GCM, ChaCha20-Poly1305, HKDF, key management |
| `IA_ASM` | Native assembly | Stub only |

```bash
# Use the ARM ASM provider
cmake -G Ninja -B cmake-build-debug -S . -DSAFE_CRYPTO_ACTIVE_PROVIDER=ARM_ASM
```

Specifying an unrecognised value is a configure-time fatal error that lists the valid choices. Adding a new provider means creating a `providers/<name>/` subdirectory with a backend struct and CMakeLists, then registering it in the top-level `SAFE_CRYPTO_ACTIVE_PROVIDER` string list.

## Stack

- **Language:** C++26
- **Build system:** CMake 3.31 + Ninja
- **Crypto backend:** MbedTLS 4.1.0 (PSA Crypto API, via FetchContent)
- **Test framework:** GoogleTest + GMock (via FetchContent)
