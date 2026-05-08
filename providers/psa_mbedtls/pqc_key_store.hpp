// SPDX-License-Identifier: Apache-2.0

#pragma once

// PQC key store for the PSA/MbedTLS backend.
// Stores raw byte keys for ML-KEM and ML-DSA indexed by slot.
// Uses ID range 0xE000+ to avoid collisions with PSA key IDs (which are
// allocated from a small integer space by psa_import_key / psa_generate_key).
//
// Layout for a generated key pair: data = [private_bytes | public_bytes]
//   priv_len = length of the private portion
//   len      = total length (priv_len + pub_len)
//
// For an imported private-only or public-only key, one of the two portions
// is zero bytes and priv_len distinguishes which portion is which.
//
// Thread-safety: a single store-level mutex serialises import, destroy, and
// the copy-out inside get_private / get_public.  Key material is copied into
// a caller-owned SecureBuffer before the lock is released, so liboqs never
// holds a pointer into store-managed heap memory.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <optional>

#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "secure_buffer.hpp"


namespace psa_mbedtls::detail {

constexpr std::size_t  pqc_key_store_capacity = 16;
constexpr unsigned int pqc_key_id_base         = 0xE000U;

enum class PqcKeyType : std::uint8_t {
    None         = 0,
    MlKemPrivate = 1,  // private key, possibly with public appended
    MlKemPublic  = 2,  // public key only
    MlDsaPrivate = 3,  // private key, possibly with public appended
    MlDsaPublic  = 4,  // public key only
};

// Largest key pair: ML-DSA-87 private (4896) + public (2592) = 7488 bytes.
constexpr std::size_t pqc_max_key_bytes = 7488U;

struct PqcKeySlot {
    // Stored on the heap to avoid large stack frames.
    CryptoByte*  data{nullptr};
    std::size_t  len{0};       // total bytes stored (priv_len + pub_len)
    std::size_t  priv_len{0};  // bytes belonging to the private key; 0 for public-only slots
    PqcKeyType   type{PqcKeyType::None};
    std::uint8_t variant{0};   // MlKemVariant or MlDsaVariant cast to uint8_t
    bool         in_use{false};
};

// Returned by pqc_key_store_get_*: owns a copy of the key bytes.
struct PqcKeyView {
    SecureBuffer  data;
    PqcKeyType    type{PqcKeyType::None};
    std::uint8_t  variant{0};
};

inline PqcKeySlot& pqc_key_slot(std::size_t idx) noexcept {
    static PqcKeySlot slots[pqc_key_store_capacity]{};  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    return slots[idx];
}

inline std::mutex& pqc_store_mutex() noexcept {
    static std::mutex m;
    return m;
}

// Import a key — private only, public only, or combined pair.
//   priv: pointer to private key bytes (may be nullptr if public-only)
//   priv_len: length of private key bytes
//   pub: pointer to public key bytes (may be nullptr if private-only)
//   pub_len: length of public key bytes
[[nodiscard]]
inline unsigned int pqc_key_store_import(PqcKeyType type, std::uint8_t variant,
                                          const CryptoByte* priv, std::size_t priv_len,
                                          const CryptoByte* pub,  std::size_t pub_len) noexcept {
    // Enforce canonical sizes: reject keys with trailing bytes or wrong length.
    switch (type) {
        case PqcKeyType::MlKemPrivate: {
            const auto v = static_cast<MlKemVariant>(variant);
            if (priv_len != ml_kem_private_key_size(v)) { return 0U; }
            if (pub_len != 0 && pub_len != ml_kem_public_key_size(v)) { return 0U; }
            break;
        }
        case PqcKeyType::MlKemPublic: {
            const auto v = static_cast<MlKemVariant>(variant);
            if (priv_len != 0 || pub_len != ml_kem_public_key_size(v)) { return 0U; }
            break;
        }
        case PqcKeyType::MlDsaPrivate: {
            const auto v = static_cast<MlDsaVariant>(variant);
            if (priv_len != ml_dsa_private_key_size(v)) { return 0U; }
            if (pub_len != 0 && pub_len != ml_dsa_public_key_size(v)) { return 0U; }
            break;
        }
        case PqcKeyType::MlDsaPublic: {
            const auto v = static_cast<MlDsaVariant>(variant);
            if (priv_len != 0 || pub_len != ml_dsa_public_key_size(v)) { return 0U; }
            break;
        }
        case PqcKeyType::None:
            return 0U;
    }
    const std::size_t total = priv_len + pub_len;
    if (total == 0 || total > pqc_max_key_bytes) { return 0U; }
    auto* buf = new (std::nothrow) CryptoByte[total];  // NOLINT(cppcoreguidelines-owning-memory)
    if (buf == nullptr) { return 0U; }
    if (priv != nullptr && priv_len > 0) {
        std::memcpy(buf, priv, priv_len);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    if (pub != nullptr && pub_len > 0) {
        std::memcpy(buf + priv_len, pub, pub_len);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    const std::lock_guard<std::mutex> lock{pqc_store_mutex()};
    for (std::size_t i = 0; i < pqc_key_store_capacity; ++i) {
        if (!pqc_key_slot(i).in_use) {
            pqc_key_slot(i).data     = buf;
            pqc_key_slot(i).len      = total;
            pqc_key_slot(i).priv_len = priv_len;
            pqc_key_slot(i).type     = type;
            pqc_key_slot(i).variant  = variant;
            pqc_key_slot(i).in_use   = true;
            return static_cast<unsigned int>(i) + pqc_key_id_base;
        }
    }
    ::detail::secure_zero(buf, total);
    delete[] buf;  // NOLINT(cppcoreguidelines-owning-memory)
    return 0U;
}

// Returns a copy of the private key bytes, or an empty optional on failure.
// The copy is made under the store lock so destroy cannot race with liboqs.
[[nodiscard]]
inline std::optional<PqcKeyView> pqc_key_store_get_private(unsigned int id) noexcept {
    if (id < pqc_key_id_base || (id - pqc_key_id_base) >= pqc_key_store_capacity) {
        return std::nullopt;
    }
    const std::size_t idx = id - pqc_key_id_base;
    const std::lock_guard<std::mutex> lock{pqc_store_mutex()};
    const PqcKeySlot& s = pqc_key_slot(idx);
    if (!s.in_use || s.priv_len == 0) { return std::nullopt; }
    try {
        SecureBuffer copy{s.priv_len};
        std::memcpy(copy.data(), s.data, s.priv_len);
        return PqcKeyView{std::move(copy), s.type, s.variant};
    } catch (...) { return std::nullopt; }
}

// Returns a copy of the public key bytes, or an empty optional on failure.
[[nodiscard]]
inline std::optional<PqcKeyView> pqc_key_store_get_public(unsigned int id) noexcept {
    if (id < pqc_key_id_base || (id - pqc_key_id_base) >= pqc_key_store_capacity) {
        return std::nullopt;
    }
    const std::size_t idx = id - pqc_key_id_base;
    const std::lock_guard<std::mutex> lock{pqc_store_mutex()};
    const PqcKeySlot& s = pqc_key_slot(idx);
    if (!s.in_use) { return std::nullopt; }
    const std::size_t pub_len = s.len - s.priv_len;
    if (pub_len == 0) { return std::nullopt; }
    try {
        SecureBuffer copy{pub_len};
        std::memcpy(copy.data(), s.data + s.priv_len, pub_len);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        return PqcKeyView{std::move(copy), s.type, s.variant};
    } catch (...) { return std::nullopt; }
}

[[nodiscard]]
inline bool pqc_key_id_is_pqc(unsigned int id) noexcept {
    return id >= pqc_key_id_base && (id - pqc_key_id_base) < pqc_key_store_capacity;
}

inline void pqc_key_store_destroy(unsigned int id) noexcept {
    if (id < pqc_key_id_base || (id - pqc_key_id_base) >= pqc_key_store_capacity) { return; }
    const std::size_t idx = id - pqc_key_id_base;
    CryptoByte* to_delete = nullptr;
    std::size_t to_delete_len = 0;
    {
        const std::lock_guard<std::mutex> lock{pqc_store_mutex()};
        PqcKeySlot& s = pqc_key_slot(idx);
        to_delete     = s.data;
        to_delete_len = s.len;
        s.data    = nullptr;
        s.len     = 0;
        s.priv_len = 0;
        s.type    = PqcKeyType::None;
        s.variant = 0;
        s.in_use  = false;
    }
    if (to_delete != nullptr) {
        ::detail::secure_zero(to_delete, to_delete_len);
        delete[] to_delete;  // NOLINT(cppcoreguidelines-owning-memory)
    }
}

}  // namespace psa_mbedtls::detail
