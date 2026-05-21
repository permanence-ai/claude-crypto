// SPDX-License-Identifier: Apache-2.0

#pragma once

// Integer key ID → EVP_PKEY* / raw-bytes slot store for the OpenSSL backend.
//
// The CryptoProvider concept uses integer KeyIds.  OpenSSL works with EVP_PKEY*
// pointers.  This file provides two stores:
//
//   OpenSslKeyStore  — asymmetric keys (EVP_PKEY*); 64 slots, IDs 1..64
//   OpenSslRawStore  — symmetric / HKDF raw-byte keys; 64 slots, IDs 65..128
//
// All stores are process-global singletons (static-local arrays, zero-init).
// Slots are reclaimed by destroy_key(); the raw store zeroizes on release.
//
// Thread-safety: a per-store mutex serialises import, destroy, and get.
//   - Raw store: get copies key bytes under the lock into an owning SecureBuffer.
//   - Asym store: get calls EVP_PKEY_up_ref() under the lock so the caller
//     holds an independent reference; the caller must call EVP_PKEY_free().

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <mutex>

#include <openssl/evp.h>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "secure_buffer.hpp"


namespace openssl_provider::detail {


// -----------------------------------------------------------------------
// Asymmetric key store — EVP_PKEY* slots.
// -----------------------------------------------------------------------

constexpr unsigned int ossl_asym_key_id_base     = 1U;
constexpr std::size_t  ossl_asym_key_store_size   = 64U;
constexpr unsigned int ossl_asym_key_id_max =
    ossl_asym_key_id_base + static_cast<unsigned int>(ossl_asym_key_store_size) - 1U;

struct OpenSslAsymSlot {
    EVP_PKEY* pkey{nullptr};
    std::uint32_t alg{0U};
    bool      in_use{false};
};

inline OpenSslAsymSlot& ossl_asym_slot(std::size_t idx) noexcept {
    static OpenSslAsymSlot slots[ossl_asym_key_store_size]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    return slots[idx]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

inline std::mutex& ossl_asym_store_mutex() noexcept {
    static std::mutex m;
    return m;
}

[[nodiscard]]
inline unsigned int ossl_asym_store_import(EVP_PKEY* pkey, std::uint32_t alg = 0U) noexcept {
    const std::scoped_lock lock{ossl_asym_store_mutex()};
    for (std::size_t i = 0; i < ossl_asym_key_store_size; ++i) {
        if (!ossl_asym_slot(i).in_use) {
            ossl_asym_slot(i).pkey   = pkey;
            ossl_asym_slot(i).alg    = alg;
            ossl_asym_slot(i).in_use = true;
            return static_cast<unsigned int>(i) + ossl_asym_key_id_base;
        }
    }
    return 0U;
}

// View returned by ossl_asym_store_get_with_alg — pkey is up_ref'd; caller must EVP_PKEY_free().
struct OpenSslAsymView {
    EVP_PKEY*     pkey{nullptr};
    std::uint32_t alg{0U};
};

// Returns a new reference to the EVP_PKEY (EVP_PKEY_up_ref'd under the lock).
// Caller must call EVP_PKEY_free() when done.
[[nodiscard]]
inline auto ossl_asym_store_get(unsigned int id) noexcept
    -> std::expected<EVP_PKEY*, CryptoError>
{
    if (id < ossl_asym_key_id_base || id > ossl_asym_key_id_max) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid asymmetric key id"));
    }
    const std::size_t idx = id - ossl_asym_key_id_base;
    const std::scoped_lock lock{ossl_asym_store_mutex()};
    if (!ossl_asym_slot(idx).in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "asymmetric key id not in use"));
    }
    EVP_PKEY* pkey = ossl_asym_slot(idx).pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        return std::unexpected(CryptoError(CryptoErrorCode::InternalError, "EVP_PKEY_up_ref failed"));
    }
    return pkey;
}

// Returns up_ref'd pkey AND alg captured atomically under one lock.
// Caller must call EVP_PKEY_free() on the returned pkey when done.
[[nodiscard]]
inline auto ossl_asym_store_get_with_alg(unsigned int id) noexcept
    -> std::expected<OpenSslAsymView, CryptoError>
{
    if (id < ossl_asym_key_id_base || id > ossl_asym_key_id_max) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid asymmetric key id"));
    }
    const std::size_t idx = id - ossl_asym_key_id_base;
    const std::scoped_lock lock{ossl_asym_store_mutex()};
    if (!ossl_asym_slot(idx).in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "asymmetric key id not in use"));
    }
    EVP_PKEY* pkey = ossl_asym_slot(idx).pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        return std::unexpected(CryptoError(CryptoErrorCode::InternalError, "EVP_PKEY_up_ref failed"));
    }
    return OpenSslAsymView{.pkey = pkey, .alg = ossl_asym_slot(idx).alg};
}

[[nodiscard]]
inline auto ossl_asym_store_alg(unsigned int id) noexcept
    -> std::expected<std::uint32_t, CryptoError>
{
    if (id < ossl_asym_key_id_base || id > ossl_asym_key_id_max) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid asymmetric key id"));
    }
    const std::size_t idx = id - ossl_asym_key_id_base;
    const std::scoped_lock lock{ossl_asym_store_mutex()};
    if (!ossl_asym_slot(idx).in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "asymmetric key id not in use"));
    }
    return ossl_asym_slot(idx).alg;
}

inline bool ossl_asym_id_valid(unsigned int id) noexcept {
    return id >= ossl_asym_key_id_base && id <= ossl_asym_key_id_max;
}

inline void ossl_asym_store_destroy(unsigned int id) noexcept {
    if (!ossl_asym_id_valid(id)) { return; }
    const std::size_t idx = id - ossl_asym_key_id_base;
    EVP_PKEY* to_free = nullptr;
    {
        const std::scoped_lock lock{ossl_asym_store_mutex()};
        OpenSslAsymSlot& s = ossl_asym_slot(idx);
        if (s.in_use) {
            to_free  = s.pkey;
            s.pkey   = nullptr;
            s.alg    = 0U;
            s.in_use = false;
        }
    }
    EVP_PKEY_free(to_free);
}


// -----------------------------------------------------------------------
// Raw-bytes key store — symmetric keys (AES, ChaCha20) and HKDF inputs.
// -----------------------------------------------------------------------

constexpr unsigned int ossl_raw_key_id_base    = ossl_asym_key_id_max + 1U;
constexpr std::size_t  ossl_raw_key_store_size  = 64U;
constexpr unsigned int ossl_raw_key_id_max =
    ossl_raw_key_id_base + static_cast<unsigned int>(ossl_raw_key_store_size) - 1U;
constexpr std::size_t  ossl_raw_key_max_bytes   = 256U;

enum class OpenSslKeyKind : uint8_t {
    None      = 0,
    Aes256    = 1,
    ChaCha20  = 2,
    Hmac      = 3,
    Derive    = 4,   // HKDF secret / PRK
};

struct OpenSslRawSlot {
    FixedSecureBuffer<ossl_raw_key_max_bytes> data{}; // NOLINT(readability-redundant-member-init)
    std::size_t     len{0};
    OpenSslKeyKind  kind{OpenSslKeyKind::None};
    bool            in_use{false};
};

struct OpenSslRawView {
    SecureBuffer    data;
    std::size_t     len{0};
    OpenSslKeyKind  kind{OpenSslKeyKind::None};
};

inline OpenSslRawSlot& ossl_raw_slot(std::size_t idx) noexcept {
    static OpenSslRawSlot slots[ossl_raw_key_store_size]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    return slots[idx]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

inline std::mutex& ossl_raw_store_mutex() noexcept {
    static std::mutex m;
    return m;
}

[[nodiscard]]
inline unsigned int ossl_raw_store_import(
    OpenSslKeyKind kind,
    const CryptoByte* key, std::size_t key_len) noexcept
{
    if (key_len > ossl_raw_key_max_bytes) { return 0U; }
    const std::scoped_lock lock{ossl_raw_store_mutex()};
    for (std::size_t i = 0; i < ossl_raw_key_store_size; ++i) {
        if (!ossl_raw_slot(i).in_use) {
            std::memcpy(ossl_raw_slot(i).data.data(), key, key_len);
            ossl_raw_slot(i).len    = key_len;
            ossl_raw_slot(i).kind   = kind;
            ossl_raw_slot(i).in_use = true;
            return static_cast<unsigned int>(i) + ossl_raw_key_id_base;
        }
    }
    return 0U;
}

// Returns a copy of the raw key bytes under the lock, or an error.
[[nodiscard]]
inline auto ossl_raw_store_get(unsigned int id) noexcept
    -> std::expected<OpenSslRawView, CryptoError>
{
    if (id < ossl_raw_key_id_base || id > ossl_raw_key_id_max) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid raw key id"));
    }
    const std::size_t idx = id - ossl_raw_key_id_base;
    const std::scoped_lock lock{ossl_raw_store_mutex()};
    const OpenSslRawSlot& s = ossl_raw_slot(idx);
    if (!s.in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "raw key id not in use"));
    }
    try {
        SecureBuffer copy{s.len};
        std::memcpy(copy.data(), s.data.data(), s.len);
        return OpenSslRawView{.data = std::move(copy), .len = s.len, .kind = s.kind};
    } catch (...) {  // NOLINT(bugprone-empty-catch) — allocation failure on noexcept path
        return std::unexpected(CryptoError(CryptoErrorCode::InternalError, "key copy allocation failed"));
    }
}

inline bool ossl_raw_id_valid(unsigned int id) noexcept {
    return id >= ossl_raw_key_id_base && id <= ossl_raw_key_id_max;
}

inline void ossl_raw_store_destroy(unsigned int id) noexcept {
    if (!ossl_raw_id_valid(id)) { return; }
    const std::size_t idx = id - ossl_raw_key_id_base;
    const std::scoped_lock lock{ossl_raw_store_mutex()};
    OpenSslRawSlot& s = ossl_raw_slot(idx);
    s.data   = FixedSecureBuffer<ossl_raw_key_max_bytes>{};
    s.len    = 0;
    s.kind   = OpenSslKeyKind::None;
    s.in_use = false;
}


}  // namespace openssl_provider::detail
