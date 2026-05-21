// SPDX-License-Identifier: Apache-2.0

#pragma once

// EC key store for the ARM ASM backend.
// Stores EC private scalars and public keys indexed by slot.
// Uses a high bit in the KeyId to distinguish EC keys from symmetric keys:
//   EC KeyId = ec_key_id_base + slot (where ec_key_id_base = 0x8000)
//
// Each EC slot holds either:
//   - A private key: curve + private scalar (big-endian bytes)
//   - A public key:  curve + uncompressed point (0x04||x||y)
//
// Thread-safety: a single store-level mutex serialises import, destroy, and the
// copy-out inside ec_key_store_get.  Key material is copied into a caller-owned
// SecureBuffer before the lock is released.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <mutex>
#include <span>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "p256_point.hpp"
#include "p384_point.hpp"
#include "p521_point.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {

constexpr std::size_t ec_key_store_capacity = 16;
constexpr unsigned int ec_key_id_base = 0x8000U;

enum class EcCurveId : uint8_t {
    None   = 0,
    P256   = 1,
    P384   = 2,
    P521   = 3,
};

enum class EcKeyKind : uint8_t {
    None    = 0,
    Private = 1,  // private scalar, big-endian raw bytes
    Public  = 2,  // uncompressed public key: 0x04 || x || y
};

constexpr std::size_t ec_max_key_bytes = 133;  // 1 + 66 + 66 = 133 (P-521 public key)

struct EcKeySlot {
    FixedSecureBuffer<ec_max_key_bytes> data;
    std::size_t len{0};
    EcCurveId curve{EcCurveId::None};
    EcKeyKind kind{EcKeyKind::None};
    bool in_use{false};
};

struct EcKeyView {
    SecureBuffer data;
    std::size_t  len{0};
    EcCurveId    curve{EcCurveId::None};
    EcKeyKind    kind{EcKeyKind::None};
};

inline EcKeySlot& ec_key_slot(std::size_t idx) noexcept {
    static std::array<EcKeySlot, ec_key_store_capacity> slots{};
    return slots[idx];
}

inline std::mutex& ec_store_mutex() noexcept {
    static std::mutex m;
    return m;
}

[[nodiscard]]
inline bool ec_key_validate(EcCurveId curve, EcKeyKind kind, // NOLINT(readability-function-size,readability-function-cognitive-complexity)
                             const CryptoByte* key, std::size_t key_len) noexcept {
    if (curve == EcCurveId::None || kind == EcKeyKind::None) { return false; }

    if (kind == EcKeyKind::Private) {
        if (curve == EcCurveId::P256) {
            if (key_len != p256_scalar_bytes) { return false; }
            Fe256 tmp{};
            return p256_scalar_sig_decode(CByteSpan<p256_scalar_bytes>{key, p256_scalar_bytes}, tmp);
        }
        if (curve == EcCurveId::P384) {
            if (key_len != p384_scalar_bytes) { return false; }
            Fe384 tmp{};
            return p384_scalar_sig_decode(CByteSpan<p384_scalar_bytes>{key, p384_scalar_bytes}, tmp);
        }
        if (curve == EcCurveId::P521) {
            if (key_len != p521_scalar_bytes) { return false; }
            Fe521 tmp{};
            return p521_scalar_sig_decode(CByteSpan<p521_scalar_bytes>{key, p521_scalar_bytes}, tmp);
        }
        return false;
    }

    if (kind == EcKeyKind::Public) {
        if (curve == EcCurveId::P256) {
            if (key_len != p256_public_key_bytes) { return false; }
            if (key[0] != 0x04U) { return false; }
            const Fe256 x = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{key + 1,  p256_scalar_bytes});
            const Fe256 y = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{key + 33, p256_scalar_bytes});
            return p256_validate_public_point(x, y);
        }
        if (curve == EcCurveId::P384) {
            if (key_len != p384_public_key_bytes) { return false; }
            if (key[0] != 0x04U) { return false; }
            const Fe384 x = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{key + 1,  p384_scalar_bytes});
            const Fe384 y = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{key + 49, p384_scalar_bytes});
            return p384_validate_public_point(x, y);
        }
        if (curve == EcCurveId::P521) {
            if (key_len != p521_public_key_bytes) { return false; }
            if (key[0] != 0x04U) { return false; }
            // key = 0x04 || x(66 bytes) || y(66 bytes): y starts at offset 1+66=67.
            constexpr std::size_t p521_y_off = 1U + p521_scalar_bytes;
            if ((key[1]          & p521_top_byte_mask) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            if ((key[p521_y_off] & p521_top_byte_mask) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const Fe521 x = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{key + 1,          p521_scalar_bytes});
            const Fe521 y = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{key + p521_y_off,  p521_scalar_bytes});
            return p521_validate_public_point(x, y);
        }
        return false;
    }

    return false;
}

[[nodiscard]]
inline unsigned int ec_key_store_import(EcCurveId curve, EcKeyKind kind,
                                         const CryptoByte* key, std::size_t key_len) noexcept {
    if (!ec_key_validate(curve, kind, key, key_len)) { return 0U; }
    const std::scoped_lock lock{ec_store_mutex()};
    for (std::size_t i = 0; i < ec_key_store_capacity; ++i) {
        if (!ec_key_slot(i).in_use) {
            std::memcpy(ec_key_slot(i).data.data(), key, key_len);
            ec_key_slot(i).len    = key_len;
            ec_key_slot(i).curve  = curve;
            ec_key_slot(i).kind   = kind;
            ec_key_slot(i).in_use = true;
            return static_cast<unsigned int>(i) + ec_key_id_base;
        }
    }
    return 0U;
}

// Returns a copy of the key bytes under the lock, or an error.
[[nodiscard]]
inline auto ec_key_store_get(unsigned int id) noexcept
    -> std::expected<EcKeyView, CryptoError>
{
    if (id < ec_key_id_base || (id - ec_key_id_base) >= ec_key_store_capacity) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid EC key id"));
    }
    const std::size_t idx = id - ec_key_id_base;
    const std::scoped_lock lock{ec_store_mutex()};
    const EcKeySlot& s = ec_key_slot(idx);
    if (!s.in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "EC key id not in use"));
    }
    try {
        SecureBuffer copy{s.len};
        std::memcpy(copy.data(), s.data.data(), s.len);
        return EcKeyView{.data = std::move(copy), .len = s.len, .curve = s.curve, .kind = s.kind};
    } catch (...) {  // NOLINT(bugprone-empty-catch) — allocation failure on noexcept path
        return std::unexpected(CryptoError(CryptoErrorCode::InternalError, "key copy allocation failed"));
    }
}

[[nodiscard]]
inline bool ec_key_id_is_ec(unsigned int id) noexcept {
    return id >= ec_key_id_base && (id - ec_key_id_base) < ec_key_store_capacity;
}

inline void ec_key_store_destroy(unsigned int id) noexcept {
    if (id < ec_key_id_base || (id - ec_key_id_base) >= ec_key_store_capacity) { return; }
    const std::size_t idx = id - ec_key_id_base;
    const std::scoped_lock lock{ec_store_mutex()};
    EcKeySlot& s = ec_key_slot(idx);
    s.data   = FixedSecureBuffer<ec_max_key_bytes>{};
    s.len    = 0;
    s.curve  = EcCurveId::None;
    s.kind   = EcKeyKind::None;
    s.in_use = false;
}

}  // namespace arm_asm::detail
