// SPDX-License-Identifier: Apache-2.0

#pragma once

// Poly1305 one-time MAC (RFC 8439 §2.5) — pure scalar __uint128_t implementation.
//
// See providers/arm_asm/poly1305.hpp for the full algorithm description.
// This file is structurally identical but uses ia_asm::detail namespace and
// removes the [[gnu::target("neon")]] attributes (arithmetic is pure integer).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace ia_asm::detail {

// Load a 16-byte value as a little-endian 128-bit unsigned integer.
struct Le128 { uint64_t lo, hi; }; // NOLINT(misc-non-private-member-variables-in-classes)

[[nodiscard]]
static inline auto load_le128(const uint8_t* p) noexcept -> Le128 {
    Le128 r{};
    std::memcpy(&r.lo, p,     8);
    std::memcpy(&r.hi, p + 8, 8);
    return r;
}

static inline void store_le128(uint8_t* p, uint64_t lo, uint64_t hi) noexcept {
    std::memcpy(p,     &lo, 8);
    std::memcpy(p + 8, &hi, 8);
}

static constexpr uint64_t mask44 = (1ULL << 44U) - 1U;
static constexpr uint64_t mask42 = (1ULL << 42U) - 1U;

struct Poly1305Limbs {
    uint64_t h0{}, h1{}, h2{}; // NOLINT(misc-non-private-member-variables-in-classes)
};

struct Poly1305Precomp {
    uint64_t r0, r1, r2;   // NOLINT(misc-non-private-member-variables-in-classes)
    uint64_t r1_20, r2_20; // NOLINT(misc-non-private-member-variables-in-classes)
};

[[nodiscard]]
static inline Poly1305Limbs block_to_limbs(uint64_t lo, uint64_t hi, uint64_t top) noexcept {
    Poly1305Limbs m;
    m.h0 = lo & mask44;
    m.h1 = ((lo >> 44U) | (hi << 20U)) & mask44;
    m.h2 = (hi >> 24U) | (top << 40U);
    return m;
}

[[nodiscard]]
static inline Poly1305Limbs clamp_r(const uint8_t r_bytes[16]) noexcept {
    FixedSecureBuffer<16> rc;
    std::memcpy(rc.data(), r_bytes, 16);
    rc[ 3] &= 0x0fU; rc[ 7] &= 0x0fU; rc[11] &= 0x0fU; rc[15] &= 0x0fU;
    rc[ 4] &= 0xfcU; rc[ 8] &= 0xfcU; rc[12] &= 0xfcU;
    uint64_t lo = 0; uint64_t hi = 0;
    std::memcpy(&lo, rc.data(),     8);
    std::memcpy(&hi, rc.data() + 8, 8);
    return Poly1305Limbs{
        .h0 = lo & mask44,
        .h1 = ((lo >> 44U) | (hi << 20U)) & mask44,
        .h2 = hi >> 24U,
    };
}

[[nodiscard]]
static inline Poly1305Precomp make_precomp(const Poly1305Limbs& r) noexcept {
    return Poly1305Precomp{
        .r0    = r.h0,
        .r1    = r.h1,
        .r2    = r.h2,
        .r1_20 = r.h1 * 20U,
        .r2_20 = r.h2 * 20U,
    };
}

static inline void poly1305_multiply_precomp(Poly1305Limbs& h,
                                              const Poly1305Precomp& p) noexcept {
    using u128 = unsigned __int128;
    const u128 d0 = (static_cast<u128>(h.h0)*p.r0) + (static_cast<u128>(h.h1)*p.r2_20) + (static_cast<u128>(h.h2)*p.r1_20);
    const u128 d1 = (static_cast<u128>(h.h0)*p.r1) + (static_cast<u128>(h.h1)*p.r0)    + (static_cast<u128>(h.h2)*p.r2_20);
    const u128 d2 = (static_cast<u128>(h.h0)*p.r2) + (static_cast<u128>(h.h1)*p.r1)    + (static_cast<u128>(h.h2)*p.r0);

    h.h0 = static_cast<uint64_t>(d0) & mask44;  const u128 c1 = d0 >> 44U;
    const u128 e1 = d1 + c1;
    h.h1 = static_cast<uint64_t>(e1) & mask44;  const u128 c2 = e1 >> 44U;
    const u128 e2 = d2 + c2;
    h.h2 = static_cast<uint64_t>(e2) & mask42;
    const uint64_t c3 = static_cast<uint64_t>(e2 >> 42U); // NOLINT(hicpp-use-auto,modernize-use-auto)
    h.h0 += c3 * 5U;
    const uint64_t c4 = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c4;
}

static inline void poly1305_add_block(Poly1305Limbs& h, uint64_t lo, uint64_t hi, uint64_t top) noexcept {
    const Poly1305Limbs m = block_to_limbs(lo, hi, top);
    h.h0 += m.h0; h.h1 += m.h1; h.h2 += m.h2;
}

static inline void poly1305_finish(const Poly1305Limbs& h_in,
                                    const uint8_t s_bytes[16],
                                    uint8_t tag[16]) noexcept
{
    uint64_t h0 = h_in.h0;
    uint64_t h1 = h_in.h1;
    uint64_t h2 = h_in.h2;
    uint64_t c = 0;
    c = h0 >> 44U; h0 &= mask44; h1 += c;
    c = h1 >> 44U; h1 &= mask44; h2 += c;
    c = h2 >> 42U; h2 &= mask42; h0 += c * 5U;
    c = h0 >> 44U; h0 &= mask44; h1 += c;

    const uint64_t g0 = h0 + 5U;
    c = g0 >> 44U;
    const uint64_t g1 = h1 + c;
    c = g1 >> 44U;
    const uint64_t g2 = h2 + c;
    const uint64_t mask = ((g2 >> 42U) != 0U) ? UINT64_MAX : 0U;

    h0 = (h0 & ~mask) | ((g0 & mask44) & mask);
    h1 = (h1 & ~mask) | ((g1 & mask44) & mask);
    h2 = (h2 & ~mask) | ((g2 & mask42) & mask);

    const uint64_t hlo = h0 | (h1 << 44U);
    const uint64_t hhi = (h1 >> 20U) | (h2 << 24U);

    const auto [slo, shi] = load_le128(s_bytes);
    const uint64_t tlo = hlo + slo;
    const uint64_t thi = hhi + shi + (tlo < hlo ? 1U : 0U);
    store_le128(tag, tlo, thi);
}

struct Poly1305Powers {
    Poly1305Precomp p1, p2, p3, p4; // NOLINT(misc-non-private-member-variables-in-classes)

    static Poly1305Powers build(const Poly1305Limbs& r) noexcept {
        Poly1305Powers pw;
        pw.p1 = make_precomp(r);
        Poly1305Limbs r2 = r;  poly1305_multiply_precomp(r2, pw.p1);
        pw.p2 = make_precomp(r2);
        Poly1305Limbs r3 = r2; poly1305_multiply_precomp(r3, pw.p1);
        pw.p3 = make_precomp(r3);
        Poly1305Limbs r4 = r3; poly1305_multiply_precomp(r4, pw.p1);
        pw.p4 = make_precomp(r4);
        return pw;
    }
};

static inline void poly1305_process_quad( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    Poly1305Limbs& h,
    uint64_t m0lo, uint64_t m0hi,
    uint64_t m1lo, uint64_t m1hi,
    uint64_t m2lo, uint64_t m2hi,
    uint64_t m3lo, uint64_t m3hi,
    const Poly1305Powers& pw) noexcept
{
    Poly1305Limbs x1 = block_to_limbs(m1lo, m1hi, 1U);
    poly1305_multiply_precomp(x1, pw.p3);
    Poly1305Limbs x2 = block_to_limbs(m2lo, m2hi, 1U);
    poly1305_multiply_precomp(x2, pw.p2);
    Poly1305Limbs x3 = block_to_limbs(m3lo, m3hi, 1U);
    poly1305_multiply_precomp(x3, pw.p1);

    poly1305_add_block(h, m0lo, m0hi, 1U);
    poly1305_multiply_precomp(h, pw.p4);

    h.h0 += x1.h0 + x2.h0 + x3.h0;
    h.h1 += x1.h1 + x2.h1 + x3.h1;
    h.h2 += x1.h2 + x2.h2 + x3.h2;
    uint64_t c = 0;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
    c = h.h1 >> 44U; h.h1 &= mask44; h.h2 += c;
    c = h.h2 >> 42U; h.h2 &= mask42; h.h0 += c * 5U;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
}

static inline void poly1305_process_pair(
    Poly1305Limbs& h,
    uint64_t m1lo, uint64_t m1hi,
    uint64_t m2lo, uint64_t m2hi,
    const Poly1305Powers& pw) noexcept
{
    Poly1305Limbs m2 = block_to_limbs(m2lo, m2hi, 1U);
    poly1305_multiply_precomp(m2, pw.p1);
    poly1305_add_block(h, m1lo, m1hi, 1U);
    poly1305_multiply_precomp(h, pw.p2);
    h.h0 += m2.h0; h.h1 += m2.h1; h.h2 += m2.h2;
    uint64_t c = 0;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
    c = h.h1 >> 44U; h.h1 &= mask44; h.h2 += c;
    c = h.h2 >> 42U; h.h2 &= mask42; h.h0 += c * 5U;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
}


inline void poly1305_mac(const uint8_t key[32], const uint8_t* msg,
                          std::size_t msg_len, uint8_t tag[16]) noexcept
{
    const Poly1305Limbs  r  = clamp_r(key);
    const Poly1305Powers pw = Poly1305Powers::build(r);
    Poly1305Limbs h{};
    std::size_t offset = 0;

    while (offset + 64 <= msg_len) {
        const auto [lo0, hi0] = load_le128(msg + offset);
        const auto [lo1, hi1] = load_le128(msg + offset + 16);
        const auto [lo2, hi2] = load_le128(msg + offset + 32);
        const auto [lo3, hi3] = load_le128(msg + offset + 48);
        poly1305_process_quad(h, lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3, pw);
        offset += 64;
    }
    if (offset + 32 <= msg_len) {
        const auto [lo1, hi1] = load_le128(msg + offset);
        const auto [lo2, hi2] = load_le128(msg + offset + 16);
        poly1305_process_pair(h, lo1, hi1, lo2, hi2, pw);
        offset += 32;
    }
    if (offset + 16 <= msg_len) {
        const auto [lo, hi] = load_le128(msg + offset);
        poly1305_add_block(h, lo, hi, 1U);
        poly1305_multiply_precomp(h, pw.p1);
        offset += 16;
    }
    if (offset < msg_len) {
        std::array<uint8_t, 16> buf{};
        std::memcpy(buf.data(), msg + offset, msg_len - offset);
        buf[msg_len - offset] = 0x01U;
        const auto [lo, hi] = load_le128(buf.data());
        poly1305_add_block(h, lo, hi, 0U);
        poly1305_multiply_precomp(h, pw.p1);
    }

    poly1305_finish(h, key + 16, tag);
}

}  // namespace ia_asm::detail
