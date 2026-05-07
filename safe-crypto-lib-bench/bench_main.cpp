// SPDX-License-Identifier: Apache-2.0

// Provider-agnostic benchmarks for safe-crypto-lib.
//
// Every benchmark is templated on CryptoProvider and instantiated for both
// RealPsaBackend and NativeAsmBackend.  Run from a Release build:
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

// Pull in provider headers. arm_asm uses NEON intrinsics incompatible with x86_64.
#ifdef SAFE_CRYPTO_PROVIDER_IA_ASM
#  include "ia_asm_backend.hpp"
using NativeAsmBackend = IaAsmBackend;
#else
#  include "arm_asm_backend.hpp"
using NativeAsmBackend = ArmAsmBackend;
#endif
#include "openssl_backend.hpp"
#include "psa_mbedtls_backend.hpp"


// Remaining library headers.
#include "aead.hpp"
#include "asymmetric.hpp"
#include "digests.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "kdf.hpp"
#include "mac.hpp"
#include "pqc_dsa.hpp"
#include "pqc_kem.hpp"
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
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha256, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA256/NATIVE");

// SHA-384
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA384/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha384, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA384/NATIVE");

// SHA-512
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA512/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha512, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA512/NATIVE");

// SHA3-256
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_256/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_256, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_256/NATIVE");

// SHA3-384
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_384/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_384, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_384/NATIVE");

// SHA3-512
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_512/PSA");
BENCHMARK_TEMPLATE(BM_Sha, ShaVariant::Sha3_512, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("SHA3_512/NATIVE");


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
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha256, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA256/NATIVE");

// HMAC-SHA-384
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA384/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha384, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA384/NATIVE");

// HMAC-SHA-512
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA512/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha512, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA512/NATIVE");

// HMAC-SHA3-256
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_256, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_256/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_256, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_256/NATIVE");

// HMAC-SHA3-384
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_384, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_384/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_384, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_384/NATIVE");

// HMAC-SHA3-512
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_512, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_512/PSA");
BENCHMARK_TEMPLATE(BM_Hmac, ShaVariant::Sha3_512, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("HMAC_SHA3_512/NATIVE");


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
BENCHMARK_TEMPLATE(BM_AesGcmEncrypt, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Enc/NATIVE");

BENCHMARK_TEMPLATE(BM_AesGcmDecrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Dec/PSA");
BENCHMARK_TEMPLATE(BM_AesGcmDecrypt, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("AES256GCM_Dec/NATIVE");


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
BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Encrypt, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Enc/NATIVE");

BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Decrypt, RealPsaBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Dec/PSA");
BENCHMARK_TEMPLATE(BM_ChaCha20Poly1305Decrypt, NativeAsmBackend)
    ->Arg(64)->Arg(1024)->Arg(16384)->Arg(262144) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("ChaCha20Poly1305_Dec/NATIVE");


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
BENCHMARK_TEMPLATE(BM_Hkdf, NativeAsmBackend)
    ->Unit(benchmark::kMicrosecond)->Name("HKDF_SHA384/NATIVE");


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
BENCHMARK_TEMPLATE(BM_RandomBytes, NativeAsmBackend)
    ->Arg(32)->Arg(256)->Arg(4096) // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ->Unit(benchmark::kMicrosecond)->Name("RandomBytes/NATIVE");


// ---------------------------------------------------------------------------
// ECDSA benchmarks (P-256, P-384, P-521)
// ---------------------------------------------------------------------------

template<EcCurve Curve, typename Provider>
static void BM_EcdsaSign(benchmark::State& state) {
    // Generate key once; sign in the loop.
    auto kp = ecdsa_generate_key_impl<Provider>(Curve);
    const auto msg = make_payload(64);
    for (auto _ : state) {
        auto result = ecdsa_sign_impl<Provider>(kp.value(), Curve, msg);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

template<EcCurve Curve, typename Provider>
static void BM_EcdsaVerify(benchmark::State& state) {
    auto kp  = ecdsa_generate_key_impl<Provider>(Curve);
    const auto msg = make_payload(64);
    auto sig = ecdsa_sign_impl<Provider>(kp.value(), Curve, msg);
    const EcPublicKey pub_only{ .public_key_der = [&]{ SecureBuffer b(kp->public_key_der.size()); std::memcpy(b.data(), kp->public_key_der.data(), b.size()); return b; }() };
    for (auto _ : state) {
        auto result = ecdsa_verify_impl<Provider>(pub_only, Curve, msg, sig.value());
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// P-256
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P256, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P256/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P256, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P256/NATIVE");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P256, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P256/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P256, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P256/NATIVE");

// P-384
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P384, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P384/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P384, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P384/NATIVE");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P384, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P384/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P384, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P384/NATIVE");

// P-521
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P521, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P521/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaSign,   EcCurve::P521, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Sign_P521/NATIVE");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P521, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P521/PSA");
BENCHMARK_TEMPLATE(BM_EcdsaVerify, EcCurve::P521, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDSA_Verify_P521/NATIVE");


// ---------------------------------------------------------------------------
// ECDH benchmarks (P-256, P-384, P-521)
// ---------------------------------------------------------------------------

template<EcCurve Curve, typename Provider>
static void BM_Ecdh(benchmark::State& state) {
    // Generate two key pairs once; compute shared secret in the loop.
    auto kp_a = ecdh_generate_key_impl<Provider>(Curve);
    auto kp_b = ecdh_generate_key_impl<Provider>(Curve);
    for (auto _ : state) {
        auto result = ecdh_compute_shared_secret_impl<Provider>(kp_a.value(), Curve, kp_b->public_key_der);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P256, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDH_P256/PSA");
BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P256, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDH_P256/NATIVE");
BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P384, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDH_P384/PSA");
BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P384, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDH_P384/NATIVE");
BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P521, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("ECDH_P521/PSA");
BENCHMARK_TEMPLATE(BM_Ecdh, EcCurve::P521, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("ECDH_P521/NATIVE");


// ---------------------------------------------------------------------------
// RSA-OAEP and RSA-PSS benchmarks (3072-bit; 4096-bit signs and verifies only)
// ---------------------------------------------------------------------------

template<RsaKeyBits KB, typename Provider>
static void BM_RsaOaepEncrypt(benchmark::State& state) {
    auto kp = generate_rsa_key_impl<KB, Provider>();
    const RsaPublicKey<KB> pub{ .public_key_der = [&]{ SecureBuffer b(kp->public_key_der.size()); std::memcpy(b.data(), kp->public_key_der.data(), b.size()); return b; }() };
    const auto pt = make_payload(64);
    for (auto _ : state) {
        auto result = rsa_oaep_encrypt_impl<KB, Provider>(pub, pt);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

template<RsaKeyBits KB, typename Provider>
static void BM_RsaOaepDecrypt(benchmark::State& state) {
    auto kp = generate_rsa_key_impl<KB, Provider>();
    const RsaPublicKey<KB> pub{ .public_key_der = [&]{ SecureBuffer b(kp->public_key_der.size()); std::memcpy(b.data(), kp->public_key_der.data(), b.size()); return b; }() };
    const auto pt = make_payload(64);
    auto ct = rsa_oaep_encrypt_impl<KB, Provider>(pub, pt);
    for (auto _ : state) {
        auto result = rsa_oaep_decrypt_impl<KB, Provider>(kp.value(), ct.value());
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

template<RsaKeyBits KB, typename Provider>
static void BM_RsaPssSign(benchmark::State& state) {
    auto kp = generate_rsa_key_impl<KB, Provider>();
    const auto msg = make_payload(64);
    for (auto _ : state) {
        auto result = rsa_pss_sign_impl<KB, Provider>(kp.value(), msg);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

template<RsaKeyBits KB, typename Provider>
static void BM_RsaPssVerify(benchmark::State& state) {
    auto kp = generate_rsa_key_impl<KB, Provider>();
    const RsaPublicKey<KB> pub{ .public_key_der = [&]{ SecureBuffer b(kp->public_key_der.size()); std::memcpy(b.data(), kp->public_key_der.data(), b.size()); return b; }() };
    const auto msg = make_payload(64);
    auto sig = rsa_pss_sign_impl<KB, Provider>(kp.value(), msg);
    for (auto _ : state) {
        auto result = rsa_pss_verify_impl<KB, Provider>(pub, msg, sig.value());
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// RSA-3072
BENCHMARK_TEMPLATE(BM_RsaOaepEncrypt, RsaKeyBits::Bits3072, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA3072_OAEP_Enc/PSA");
BENCHMARK_TEMPLATE(BM_RsaOaepEncrypt, RsaKeyBits::Bits3072, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA3072_OAEP_Enc/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaOaepDecrypt, RsaKeyBits::Bits3072, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA3072_OAEP_Dec/PSA");
BENCHMARK_TEMPLATE(BM_RsaOaepDecrypt, RsaKeyBits::Bits3072, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA3072_OAEP_Dec/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaPssSign,     RsaKeyBits::Bits3072, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA3072_PSS_Sign/PSA");
BENCHMARK_TEMPLATE(BM_RsaPssSign,     RsaKeyBits::Bits3072, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA3072_PSS_Sign/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaPssVerify,   RsaKeyBits::Bits3072, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA3072_PSS_Verify/PSA");
BENCHMARK_TEMPLATE(BM_RsaPssVerify,   RsaKeyBits::Bits3072, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA3072_PSS_Verify/NATIVE");

// RSA-4096
BENCHMARK_TEMPLATE(BM_RsaOaepEncrypt, RsaKeyBits::Bits4096, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA4096_OAEP_Enc/PSA");
BENCHMARK_TEMPLATE(BM_RsaOaepEncrypt, RsaKeyBits::Bits4096, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA4096_OAEP_Enc/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaOaepDecrypt, RsaKeyBits::Bits4096, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA4096_OAEP_Dec/PSA");
BENCHMARK_TEMPLATE(BM_RsaOaepDecrypt, RsaKeyBits::Bits4096, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA4096_OAEP_Dec/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaPssSign,     RsaKeyBits::Bits4096, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA4096_PSS_Sign/PSA");
BENCHMARK_TEMPLATE(BM_RsaPssSign,     RsaKeyBits::Bits4096, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA4096_PSS_Sign/NATIVE");
BENCHMARK_TEMPLATE(BM_RsaPssVerify,   RsaKeyBits::Bits4096, RealPsaBackend)->Unit(benchmark::kMicrosecond)->Name("RSA4096_PSS_Verify/PSA");
BENCHMARK_TEMPLATE(BM_RsaPssVerify,   RsaKeyBits::Bits4096, NativeAsmBackend) ->Unit(benchmark::kMicrosecond)->Name("RSA4096_PSS_Verify/NATIVE");


// ---------------------------------------------------------------------------
// PQC benchmarks — ML-DSA and ML-KEM across all three providers.
// Guarded by SAFE_CRYPTO_PQC_LIBOQS (ARM/PSA) + OpenSslBackend (always).
// ---------------------------------------------------------------------------

#if defined(SAFE_CRYPTO_PQC_LIBOQS)

// ML-DSA keygen
template<MlDsaVariant V, typename Provider>
static void BM_MlDsaKeygen(benchmark::State& state) {
    for (auto _ : state) {
        auto result = ml_dsa_generate_key_impl<V, Provider>();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// ML-DSA sign (keygen once, sign in loop)
template<MlDsaVariant V, typename Provider>
static void BM_MlDsaSign(benchmark::State& state) {
    auto kp = ml_dsa_generate_key_impl<V, Provider>();
    const auto msg = make_payload(64);
    for (auto _ : state) {
        auto result = ml_dsa_sign_impl<V, Provider>(*kp, msg);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// ML-DSA verify (keygen + sign once, verify in loop)
template<MlDsaVariant V, typename Provider>
static void BM_MlDsaVerify(benchmark::State& state) {
    auto kp  = ml_dsa_generate_key_impl<V, Provider>();
    const auto msg = make_payload(64);
    auto sig = ml_dsa_sign_impl<V, Provider>(*kp, msg);
    const MlDsaPublicKey<V> pub{
        .public_key = [&]{ SecureBuffer b(kp->public_key.size()); std::memcpy(b.data(), kp->public_key.data(), b.size()); return b; }()
    };
    for (auto _ : state) {
        auto result = ml_dsa_verify_impl<V, Provider>(pub, msg, *sig);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// ML-KEM keygen
template<MlKemVariant V, typename Provider>
static void BM_MlKemKeygen(benchmark::State& state) {
    for (auto _ : state) {
        auto result = ml_kem_generate_key_impl<V, Provider>();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// ML-KEM encapsulate (keygen once, encap in loop)
template<MlKemVariant V, typename Provider>
static void BM_MlKemEncap(benchmark::State& state) {
    auto kp = ml_kem_generate_key_impl<V, Provider>();
    const MlKemPublicKey<V> pub{
        .public_key = [&]{ SecureBuffer b(kp->public_key.size()); std::memcpy(b.data(), kp->public_key.data(), b.size()); return b; }()
    };
    for (auto _ : state) {
        auto result = ml_kem_encapsulate_impl<V, Provider>(pub);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// ML-KEM decapsulate (keygen + encap once, decap in loop)
template<MlKemVariant V, typename Provider>
static void BM_MlKemDecap(benchmark::State& state) {
    auto kp  = ml_kem_generate_key_impl<V, Provider>();
    const MlKemPublicKey<V> pub{
        .public_key = [&]{ SecureBuffer b(kp->public_key.size()); std::memcpy(b.data(), kp->public_key.data(), b.size()); return b; }()
    };
    auto enc = ml_kem_encapsulate_impl<V, Provider>(pub);
    for (auto _ : state) {
        auto result = ml_kem_decapsulate_impl<V, Provider>(*kp, enc->ciphertext);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));
}

// --- ML-DSA-44 ---
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa44, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa44, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa44, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa44, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Sign/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa44, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Sign/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa44, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Sign/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa44, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Verify/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa44, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Verify/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa44, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA44_Verify/OSSL");

// --- ML-DSA-65 ---
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa65, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa65, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa65, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa65, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Sign/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa65, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Sign/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa65, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Sign/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa65, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Verify/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa65, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Verify/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa65, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA65_Verify/OSSL");

// --- ML-DSA-87 ---
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa87, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa87, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaKeygen, MlDsaVariant::Dsa87, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa87, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Sign/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa87, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Sign/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaSign,   MlDsaVariant::Dsa87, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Sign/OSSL");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa87, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Verify/PSA");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa87, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Verify/NATIVE");
BENCHMARK_TEMPLATE(BM_MlDsaVerify, MlDsaVariant::Dsa87, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLDSA87_Verify/OSSL");

// --- ML-KEM-512 ---
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem512, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem512, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem512, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem512, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Encap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem512, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Encap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem512, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Encap/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem512, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Decap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem512, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Decap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem512, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM512_Decap/OSSL");

// --- ML-KEM-768 ---
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem768, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem768, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem768, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem768, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Encap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem768, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Encap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem768, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Encap/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem768, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Decap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem768, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Decap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem768, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM768_Decap/OSSL");

// --- ML-KEM-1024 ---
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem1024, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Keygen/PSA");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem1024, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Keygen/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemKeygen, MlKemVariant::Kem1024, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Keygen/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem1024, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Encap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem1024, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Encap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemEncap,  MlKemVariant::Kem1024, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Encap/OSSL");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem1024, RealPsaBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Decap/PSA");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem1024, NativeAsmBackend)  ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Decap/NATIVE");
BENCHMARK_TEMPLATE(BM_MlKemDecap,  MlKemVariant::Kem1024, OpenSslBackend) ->Unit(benchmark::kMicrosecond)->Name("MLKEM1024_Decap/OSSL");

#endif  // SAFE_CRYPTO_PQC_LIBOQS


BENCHMARK_MAIN(); // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
