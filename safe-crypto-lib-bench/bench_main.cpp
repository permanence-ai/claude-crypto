/*
Copyright Permanence AI, 2026. All rights reserved.

*/

// Provider-agnostic benchmarks for safe-crypto-lib.
//
// Every benchmark is templated on CryptoProvider and instantiated for both
// RealPsaBackend and ArmAsmBackend.  Run from a Release build:
//
//   cmake -G Ninja -B cmake-build-release -S . -DCMAKE_BUILD_TYPE=Release
//   cmake --build cmake-build-release --target safe_crypto_lib_bench
//   ./cmake-build-release/safe-crypto-lib-bench/safe_crypto_lib_bench
//
// Add --benchmark_filter=<regex> to run a subset.
// Add --benchmark_format=json  to emit machine-readable output.
//
// Throughput is reported as bytes/second via SetBytesProcessed so Google
// Benchmark displays GB/s or MB/s automatically.  Latency is visible from
// the wall-clock time per iteration.
//
// Payload sizes: 64 B (typical single-block), 1 KiB, 16 KiB, 256 KiB.
// The range is exposed via BENCHMARK_TEMPLATE(...)->Arg(...) calls.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <benchmark/benchmark.h>

// Library headers must come before provider headers: defs.hpp and sha_variant.hpp
// define types and constants (CryptoByte, sha384_size_bytes, ...) that the
// arm_asm provider headers reference without re-including.
#include "defs.hpp"
#include "sha_variant.hpp"
#include "secure_buffer.hpp"

// Always pull in both provider headers so we can instantiate both.
#include "arm_asm_backend.hpp"
#include "psa_mbedtls_backend.hpp"

// Remaining library headers.
#include "aead.hpp"
#include "digests.hpp"
#include "kdf.hpp"
#include "mac.hpp"
#include "random.hpp"


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Fill a SecureBuffer with a deterministic byte pattern (no crypto needed).
static SecureBuffer make_payload(std::size_t n) {
    SecureBuffer buf(n);
    for (std::size_t i = 0; i < n; ++i) {
        buf.data()[i] = static_cast<CryptoByte>(i & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return buf;
}

// 32-byte key filled with a fixed pattern.
template<std::size_t N>
static FixedSecureBuffer<N> make_key() {
    FixedSecureBuffer<N> k;
    for (std::size_t i = 0; i < N; ++i) {
        k.data()[i] = static_cast<CryptoByte>(0xA0U ^ (i & 0xFFU)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return k;
}

// 48-byte HMAC key as a SecureBuffer (HMAC key is variable-length).
static SecureBuffer make_hmac_key(std::size_t len = 48) {
    SecureBuffer k(len);
    for (std::size_t i = 0; i < len; ++i) {
        k.data()[i] = static_cast<CryptoByte>(0xB0U ^ (i & 0xFFU)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return k;
}


// ---------------------------------------------------------------------------
// SHA-2 digest benchmarks
// ---------------------------------------------------------------------------

template<ShaVariant V, typename Provider>
static void BM_Sha(benchmark::State& state) {
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    for (auto _ : state) {
        auto result = sha_impl<V, Provider>(payload);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

// SHA-256
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA256/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha256, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA256/ARM");

// SHA-384
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA384/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha384, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA384/ARM");

// SHA-512
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA512/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha512, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA512/ARM");

// SHA3-256
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_256/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_256, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_256/ARM");

// SHA3-384
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_384/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_384, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_384/ARM");

// SHA3-512
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_512/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_512, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_512/ARM");


// ---------------------------------------------------------------------------
// HMAC benchmarks
// ---------------------------------------------------------------------------

template<ShaVariant V, typename Provider>
static void BM_Hmac(benchmark::State& state) {
    const auto key     = make_hmac_key();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    for (auto _ : state) {
        auto result = hmac_generate_impl<V, Provider>(key, payload);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

// HMAC-SHA-256
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA256/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha256, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA256/ARM");

// HMAC-SHA-384
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA384/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha384, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA384/ARM");

// HMAC-SHA-512
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA512/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha512, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA512/ARM");

// HMAC-SHA3-256
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_256/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_256, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_256/ARM");

// HMAC-SHA3-384
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_384/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_384, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_384/ARM");

// HMAC-SHA3-512
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_512/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_512, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_512/ARM");


// ---------------------------------------------------------------------------
// AES-256-GCM benchmarks
// ---------------------------------------------------------------------------

template<typename Provider>
static void BM_AesGcmEncrypt(benchmark::State& state) {
    const auto key     = make_key<aes256_key_size_bytes>();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    for (auto _ : state) {
        auto result = aes256_gcm_encrypt_impl<Provider>(key, payload);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

template<typename Provider>
static void BM_AesGcmDecrypt(benchmark::State& state) {
    const auto key     = make_key<aes256_key_size_bytes>();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    // Pre-encrypt once; the decrypt benchmark measures only the decrypt path.
    auto enc = aes256_gcm_encrypt_impl<Provider>(key, payload);
    for (auto _ : state) {
        auto result = aes256_gcm_decrypt_impl<Provider>(key, *enc);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK_TEMPLATE(BM_AesGcmEncrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Enc/PSA");
BENCHMARK_TEMPLATE(BM_AesGcmEncrypt, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Enc/ARM");

BENCHMARK_TEMPLATE(BM_AesGcmDecrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Dec/PSA");
BENCHMARK_TEMPLATE(BM_AesGcmDecrypt, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Dec/ARM");


// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 benchmarks
// ---------------------------------------------------------------------------

template<typename Provider>
static void BM_ChaCha20Poly1305Encrypt(benchmark::State& state) {
    const auto key     = make_key<chacha20_key_size_bytes>();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    for (auto _ : state) {
        auto result = chacha20_poly1305_encrypt_impl<Provider>(key, payload);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

template<typename Provider>
static void BM_ChaCha20Poly1305Decrypt(benchmark::State& state) {
    const auto key     = make_key<chacha20_key_size_bytes>();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)));
    auto enc = chacha20_poly1305_encrypt_impl<Provider>(key, payload);
    for (auto _ : state) {
        auto result = chacha20_poly1305_decrypt_impl<Provider>(key, *enc);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Encrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Enc/PSA");
BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Encrypt, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Enc/ARM");

BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Decrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Dec/PSA");
BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Decrypt, ArmAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Dec/ARM");


// ---------------------------------------------------------------------------
// HKDF benchmarks (output_length = 48 bytes, fixed 64-byte IKM)
// ---------------------------------------------------------------------------
// HKDF performance is dominated by the HMAC calls, not by payload size, so we
// benchmark at a single representative output length and vary nothing else.

// Raw byte arrays used to rebuild SecureBuffers each iteration (SecureBuffer is move-only).
static constexpr std::size_t hkdf_ikm_len  = 128;
static constexpr std::size_t hkdf_salt_len =  13;
static constexpr std::size_t hkdf_info_len =  10;

template<typename Provider>
static void BM_Hkdf(benchmark::State& state) {
    // Pre-build raw byte arrays; reconstruct SecureBuffers each iteration.
    uint8_t ikm_raw[hkdf_ikm_len]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < hkdf_ikm_len; ++i) {
        ikm_raw[i] = static_cast<uint8_t>(i & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    uint8_t salt_raw[hkdf_salt_len]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < hkdf_salt_len; ++i) {
        salt_raw[i] = static_cast<uint8_t>(i); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    uint8_t info_raw[hkdf_info_len]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < hkdf_info_len; ++i) {
        info_raw[i] = static_cast<uint8_t>(0xF0U | i); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    constexpr std::size_t output_len = 48;
    for (auto _ : state) {
        SecureBuffer ikm(hkdf_ikm_len);
        std::memcpy(ikm.data(), ikm_raw, hkdf_ikm_len); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
        SecureBuffer salt(hkdf_salt_len);
        std::memcpy(salt.data(), salt_raw, hkdf_salt_len); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
        SecureBuffer info(hkdf_info_len);
        std::memcpy(info.data(), info_raw, hkdf_info_len); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

        auto result = derive_key_impl<Provider>(
            output_len,
            std::optional<SecureBuffer>(std::move(ikm)),
            std::optional<SecureBuffer>(std::move(salt)),
            std::optional<SecureBuffer>(std::move(info)));
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

BENCHMARK_TEMPLATE(BM_Hkdf, RealPsaBackend)
    ->Unit(benchmark::kMicrosecond)->Name("HKDF_SHA384/PSA");
BENCHMARK_TEMPLATE(BM_Hkdf, ArmAsmBackend)
    ->Unit(benchmark::kMicrosecond)->Name("HKDF_SHA384/ARM");


// ---------------------------------------------------------------------------
// Random-bytes benchmark (single provider: delegates to OS CSPRNG either way)
// ---------------------------------------------------------------------------

template<typename Provider>
static void BM_RandomBytes(benchmark::State& state) {
    for (auto _ : state) {
        auto result = random_bytes_impl<Provider>(
            static_cast<std::size_t>(state.range(0)));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK_TEMPLATE(BM_RandomBytes, RealPsaBackend)
    ->Arg(32)->Arg(256)->Arg(4096) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("RandomBytes/PSA");
BENCHMARK_TEMPLATE(BM_RandomBytes, ArmAsmBackend)
    ->Arg(32)->Arg(256)->Arg(4096) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("RandomBytes/ARM");


BENCHMARK_MAIN(); // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
