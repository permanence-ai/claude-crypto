/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// EC key store for the ARM ASM backend.
// Stores EC private scalars and public keys indexed by slot.
// Uses a high bit in the KeyId to distinguish EC keys from symmetric keys:
//   EC KeyId = ec_key_id_base + slot (where ec_key_id_base = 0x8000)
//
// Each EC slot holds either:
//   - A private key: curve + private scalar (big-endian bytes)
//   - A public key:  curve + uncompressed point (0x04||x||y)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {

constexpr std::size_t ec_key_store_capacity = 16;
constexpr unsigned int ec_key_id_base = 0x8000U;

enum class EcCurveId : uint8_t {
    None   = 0,
    P256   = 1,
    P384   = 2,
};

enum class EcKeyKind : uint8_t {
    None    = 0,
    Private = 1,  // private scalar, big-endian raw bytes
    Public  = 2,  // uncompressed public key: 0x04 || x || y
};

constexpr std::size_t ec_max_key_bytes = 97;  // 1 + 48 + 48 = 97 (P-384 public key)

struct EcKeySlot {
    FixedSecureBuffer<ec_max_key_bytes> data;
    std::size_t len{0};
    EcCurveId curve{EcCurveId::None};
    EcKeyKind kind{EcKeyKind::None};
    bool in_use{false};
};

inline EcKeySlot& ec_key_slot(std::size_t idx) noexcept {
    static EcKeySlot slots[ec_key_store_capacity]{};  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    return slots[idx];
}

[[nodiscard]]
inline unsigned int ec_key_store_import(EcCurveId curve, EcKeyKind kind,
                                         const CryptoByte* key, std::size_t key_len) noexcept {
    if (key_len > ec_max_key_bytes) { return 0U; }
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

[[nodiscard]]
inline bool ec_key_store_get(unsigned int id,
                              EcCurveId* out_curve, EcKeyKind* out_kind,
                              const CryptoByte** out_key, std::size_t* out_len) noexcept {
    if (id < ec_key_id_base || (id - ec_key_id_base) >= ec_key_store_capacity) { return false; }
    const std::size_t idx = id - ec_key_id_base;
    EcKeySlot& s = ec_key_slot(idx);
    if (!s.in_use) { return false; }
    *out_curve = s.curve;
    *out_kind  = s.kind;
    *out_key   = s.data.data();
    *out_len   = s.len;
    return true;
}

[[nodiscard]]
inline bool ec_key_id_is_ec(unsigned int id) noexcept {
    return id >= ec_key_id_base && (id - ec_key_id_base) < ec_key_store_capacity;
}

inline void ec_key_store_destroy(unsigned int id) noexcept {
    if (id < ec_key_id_base || (id - ec_key_id_base) >= ec_key_store_capacity) { return; }
    const std::size_t idx = id - ec_key_id_base;
    EcKeySlot& s = ec_key_slot(idx);
    s.data   = FixedSecureBuffer<ec_max_key_bytes>{};
    s.len    = 0;
    s.curve  = EcCurveId::None;
    s.kind   = EcKeyKind::None;
    s.in_use = false;
}

}  // namespace arm_asm::detail
