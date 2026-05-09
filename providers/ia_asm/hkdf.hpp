// SPDX-License-Identifier: Apache-2.0

#pragma once

// HKDF (RFC 5869) and HKDF-Expand using HMAC-SHA-384.
//
// See providers/arm_asm/hkdf.hpp for the full algorithm description.
// This file is structurally identical but uses ia_asm::detail namespace.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"
#include "hmac.hpp"
#include "key_store.hpp"
#include "secure_buffer.hpp"


namespace ia_asm::detail {

constexpr std::size_t hkdf_hash_len   = sha384_size_bytes;  // 48
constexpr std::size_t hkdf_max_output = 255 * hkdf_hash_len;
constexpr std::size_t hkdf_max_salt   = 256;
constexpr std::size_t hkdf_max_info   = 256;

enum class HkdfAlg   : uint8_t { None, Hkdf, HkdfExpand };
enum class HkdfPhase : uint8_t { Init, Setup, KeySet, SaltSet, InfoSet };

struct HkdfState {
    HkdfAlg   alg{HkdfAlg::None};     // NOLINT(misc-non-private-member-variables-in-classes)
    HkdfPhase phase{HkdfPhase::Init};  // NOLINT(misc-non-private-member-variables-in-classes)
    unsigned int key_id{0};            // NOLINT(misc-non-private-member-variables-in-classes)

    FixedSecureBuffer<hkdf_max_salt> salt; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t salt_len{0}; // NOLINT(misc-non-private-member-variables-in-classes)
    bool salt_set{false};    // NOLINT(misc-non-private-member-variables-in-classes)

    FixedSecureBuffer<hkdf_max_info> info; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t info_len{0}; // NOLINT(misc-non-private-member-variables-in-classes)

    void zeroize() noexcept {
        alg      = HkdfAlg::None;
        phase    = HkdfPhase::Init;
        key_id   = 0;
        salt_len = 0;
        salt_set = false;
        info_len = 0;
        salt     = FixedSecureBuffer<hkdf_max_salt>{};
        info     = FixedSecureBuffer<hkdf_max_info>{};
    }
};


[[nodiscard]]
inline int hkdf_setup(HkdfState* op, HkdfAlg alg) noexcept {
    if (op == nullptr) { return 1; }
    op->zeroize();
    op->alg   = alg;
    op->phase = HkdfPhase::Setup;
    return 0;
}

[[nodiscard]]
inline int hkdf_input_key(HkdfState* op, unsigned int key_id) noexcept {
    if (op == nullptr) { return 1; }
    if (op->phase != HkdfPhase::Setup) { return 1; }
    op->key_id = key_id;
    op->phase  = HkdfPhase::KeySet;
    return 0;
}

[[nodiscard]]
inline int hkdf_input_bytes(HkdfState* op, unsigned int step,
                             const uint8_t* data, std::size_t len) noexcept {
    if (op == nullptr) { return 1; }
    constexpr unsigned int step_salt = 0U;
    constexpr unsigned int step_info = 1U;

    if (step == step_salt) {
        if (op->phase != HkdfPhase::Setup) { return 1; }
        if (len > hkdf_max_salt) { return 1; }
        if (data != nullptr && len > 0) {
            std::memcpy(op->salt.data(), data, len);
        }
        op->salt_len = len;
        op->salt_set = true;
        return 0;
    }
    if (step == step_info) {
        if (op->phase != HkdfPhase::KeySet) { return 1; }
        if (len > hkdf_max_info) { return 1; }
        if (data != nullptr && len > 0) {
            std::memcpy(op->info.data(), data, len);
        }
        op->info_len = len;
        op->phase    = HkdfPhase::InfoSet;
        return 0;
    }
    return 1;
}

[[nodiscard]]
inline int hkdf_expand(const uint8_t* prk, std::size_t prk_len,
                        const uint8_t* info, std::size_t info_len,
                        uint8_t* out, std::size_t out_len) noexcept {
    if (out_len == 0 || out_len > hkdf_max_output) { return 1; }

    FixedSecureBuffer<hkdf_hash_len> t;
    std::size_t written = 0;
    uint8_t counter = 1;

    FixedSecureBuffer<hkdf_hash_len + hkdf_max_info + 1> msg;

    while (written < out_len) {
        std::size_t msg_len = 0;
        if (counter > 1) {
            std::memcpy(msg.data(), t.data(), hkdf_hash_len);
            msg_len += hkdf_hash_len;
        }
        if (info_len > 0 && info != nullptr) {

            std::memcpy(msg.data() + msg_len, info, info_len);
            msg_len += info_len;
        }

        msg[msg_len] = counter;
        msg_len += 1;

        hmac_sha384(prk, prk_len, msg.data(), msg_len, t.data());

        const std::size_t copy_len = std::min(hkdf_hash_len, out_len - written);

        std::memcpy(out + written, t.data(), copy_len);
        written += copy_len;
        ++counter;
    }

    return 0;
}

[[nodiscard]]
inline int hkdf_output_bytes(HkdfState* op, uint8_t* out, std::size_t len) noexcept {
    if (op == nullptr) { return 1; }
    if (op->phase != HkdfPhase::InfoSet) { return 1; }
    if (len == 0 || len > hkdf_max_output) { return 1; }

    const CryptoByte* ikm = nullptr;
    std::size_t ikm_len = 0;
    if (!key_store_get(op->key_id, &ikm, &ikm_len)) { return 1; }

    if (op->alg == HkdfAlg::HkdfExpand) {
        return hkdf_expand(ikm, ikm_len, op->info.data(), op->info_len, out, len);
    }

    FixedSecureBuffer<hkdf_hash_len> prk;
    if (op->salt_set && op->salt_len > 0) {
        hmac_sha384(op->salt.data(), op->salt_len, ikm, ikm_len, prk.data());
    } else {
        const FixedSecureBuffer<hkdf_hash_len> zero_salt;
        hmac_sha384(zero_salt.data(), hkdf_hash_len, ikm, ikm_len, prk.data());
    }

    return hkdf_expand(prk.data(), hkdf_hash_len, op->info.data(), op->info_len, out, len);
}

}  // namespace ia_asm::detail
