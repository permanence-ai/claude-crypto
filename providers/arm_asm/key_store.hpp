// SPDX-License-Identifier: Apache-2.0

#pragma once

// Minimal key store for the ARM ASM backend.
// Stores raw symmetric key bytes indexed by a KeyId slot number.
// KeyId 0 is the null key; valid IDs are 1..key_store_capacity.
//
// This is intentionally simple: it covers HMAC and AES key storage.
//
// Thread-safety: a single store-level mutex serialises import, destroy, and the
// copy-out inside key_store_get.  Key material is copied into a caller-owned
// SecureBuffer before the lock is released, so callers never hold a pointer
// into store-managed memory.

#include <array>
#include <cstddef>
#include <cstring>
#include <expected>
#include <mutex>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "secure_buffer.hpp"



namespace arm_asm::detail {

constexpr std::size_t key_store_capacity = 16;
constexpr std::size_t key_store_max_bytes = 512;  // enough for any symmetric key

struct KeySlot {
    FixedSecureBuffer<key_store_max_bytes> data;
    std::size_t len{0};
    bool in_use{false};
};

struct KeyView {
    SecureBuffer data;
    std::size_t  len{0};
};

// Global key store — one instance per process.
inline KeySlot& key_slot(std::size_t idx) noexcept {
    static std::array<KeySlot, key_store_capacity> slots{};
    return slots[idx];
}

inline std::mutex& sym_store_mutex() noexcept {
    static std::mutex m;
    return m;
}

// Returns 0 on failure, otherwise a KeyId in [1..capacity].
[[nodiscard]]
inline unsigned int key_store_import(const CryptoByte* key, std::size_t key_len) noexcept {
    if (key_len > key_store_max_bytes) { return 0U; }
    const std::scoped_lock lock{sym_store_mutex()};
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

// Returns a copy of the key bytes under the lock, or an error.
[[nodiscard]]
inline auto key_store_get(unsigned int id) noexcept
    -> std::expected<KeyView, CryptoError>
{
    if (id == 0 || id > key_store_capacity) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "invalid symmetric key id"));
    }
    const std::scoped_lock lock{sym_store_mutex()};
    const KeySlot& s = key_slot(id - 1);
    if (!s.in_use) {
        return std::unexpected(CryptoError(CryptoErrorCode::InvalidArgument, "symmetric key id not in use"));
    }
    try {
        SecureBuffer copy{s.len};
        std::memcpy(copy.data(), s.data.data(), s.len);
        return KeyView{.data = std::move(copy), .len = s.len};
    } catch (...) {  // NOLINT(bugprone-empty-catch) — allocation failure on noexcept path
        return std::unexpected(CryptoError(CryptoErrorCode::InternalError, "key copy allocation failed"));
    }
}

// Zeroizes and frees the slot.
inline void key_store_destroy(unsigned int id) noexcept {
    if (id == 0 || id > key_store_capacity) { return; }
    const std::scoped_lock lock{sym_store_mutex()};
    KeySlot& s = key_slot(id - 1);
    // FixedSecureBuffer zeroizes its data on destruction; assign a fresh one to scrub now.
    s.data   = FixedSecureBuffer<key_store_max_bytes>{};
    s.len    = 0;
    s.in_use = false;
}

}  // namespace arm_asm::detail
