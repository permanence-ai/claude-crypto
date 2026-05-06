// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// Minimal key store for the IA ASM backend.
// Stores raw symmetric key bytes indexed by a KeyId slot number.
// KeyId 0 is the null key; valid IDs are 1..key_store_capacity.

#include <cstddef>
#include <cstring>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace ia_asm::detail {

constexpr std::size_t key_store_capacity  = 16; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
constexpr std::size_t key_store_max_bytes = 512; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

struct KeySlot {
    FixedSecureBuffer<key_store_max_bytes> data;
    std::size_t len;
    bool in_use;
};

inline KeySlot& key_slot(std::size_t idx) noexcept {
    static KeySlot slots[key_store_capacity]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    return slots[idx]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

[[nodiscard]]
inline unsigned int key_store_import(const CryptoByte* key, std::size_t key_len) noexcept {
    if (key_len > key_store_max_bytes) { return 0U; }
    for (std::size_t i = 0; i < key_store_capacity; ++i) {
        if (!key_slot(i).in_use) {
            std::memcpy(key_slot(i).data.data(), key, key_len);
            key_slot(i).len    = key_len;
            key_slot(i).in_use = true;
            return static_cast<unsigned int>(i + 1);
        }
    }
    return 0U;
}

[[nodiscard]]
inline bool key_store_get(unsigned int id,
                           const CryptoByte** out_key,
                           std::size_t* out_len) noexcept {
    if (id == 0 || id > key_store_capacity) { return false; }
    KeySlot& s = key_slot(id - 1);
    if (!s.in_use) { return false; }
    *out_key = s.data.data();
    *out_len = s.len;
    return true;
}

inline void key_store_destroy(unsigned int id) noexcept {
    if (id == 0 || id > key_store_capacity) { return; }
    KeySlot& s = key_slot(id - 1);
    s.data   = FixedSecureBuffer<key_store_max_bytes>{};
    s.len    = 0;
    s.in_use = false;
}

}  // namespace ia_asm::detail
