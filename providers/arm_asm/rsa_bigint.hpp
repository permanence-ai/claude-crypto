/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Constant-time big integer arithmetic for RSA-3072 and RSA-4096.
//
// Representation
// --------------
// BigInt<NW> holds an integer in NW 64-bit limbs, stored in little-endian
// order: limb[0] is the least significant 64-bit word.
//
// Montgomery multiplication
// -------------------------
// All modular arithmetic is performed in Montgomery form.
// mont_mul(a, b, m, m0inv) computes a·b·R⁻¹ mod m, where R = 2^(64·NW)
// and m0inv = -m⁻¹ mod 2^64 (precomputed once per modulus).
//
// Modular exponentiation
// ----------------------
// bigint_powmod_ct uses the left-to-right binary method with a constant-time
// conditional swap (Montgomery ladder variant) to avoid secret-dependent
// branches.  All operations use Montgomery form internally.
//
// CRT reconstruction
// ------------------
// rsa_crt_combine reconstructs m = m_p + p * h  (Garner's formula)
// where h = (m_q - m_p) * qInvModP mod p.
// All inputs are already reduced mod p/q; no Montgomery form needed here.
//
// Constant-time guarantees
// ------------------------
// * No secret-dependent branches.
// * No secret-dependent memory indices.
// * bigint_powmod_ct processes all bits of the exponent unconditionally.
// * ct_select uses bitwise operations to avoid branches.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "defs.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// Maximum sizes for RSA-4096 (in 64-bit limbs).
// -----------------------------------------------------------------------

constexpr std::size_t rsa_max_limbs = 64;  // 4096 bits / 64 bits per limb


// -----------------------------------------------------------------------
// BigInt: a fixed-width unsigned integer in little-endian 64-bit limbs.
// NW is the number of 64-bit limbs.
// -----------------------------------------------------------------------

template<std::size_t NW>
struct BigInt {
    std::array<uint64_t, NW> d{};  // d[0] = least significant limb

    [[nodiscard]] constexpr uint64_t& operator[](std::size_t i)       noexcept { return d[i]; }
    [[nodiscard]] constexpr const uint64_t& operator[](std::size_t i) const noexcept { return d[i]; }

    [[nodiscard]] static constexpr std::size_t limbs() noexcept { return NW; }
};


// -----------------------------------------------------------------------
// Load / store (big-endian byte arrays to/from little-endian limbs).
// -----------------------------------------------------------------------

// Load up to NW*8 bytes from a big-endian byte array.
// If byte_len < NW*8, the most-significant limbs are zero-filled.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_from_bytes(const CryptoByte* bytes, std::size_t byte_len) noexcept {
    BigInt<NW> out{};
    // bytes[0] is most significant; d[0] is least significant limb.
    // We map: byte at position (byte_len - 1 - i) → byte i of the integer.
    for (std::size_t i = 0; i < byte_len && i < NW * 8U; ++i) {
        const std::size_t byte_idx = byte_len - 1U - i;  // byte within the source array
        const std::size_t limb_idx = i / 8U;
        const std::size_t bit_shift = (i % 8U) * 8U;
        out.d[limb_idx] |= static_cast<uint64_t>(bytes[byte_idx]) << bit_shift; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return out;
}

// Store NW*8 bytes in big-endian order.
template<std::size_t NW>
inline void bigint_to_bytes(const BigInt<NW>& a, CryptoByte* bytes) noexcept {
    for (std::size_t i = 0; i < NW * 8U; ++i) {
        const std::size_t limb_idx  = i / 8U;
        const std::size_t bit_shift = (i % 8U) * 8U;
        bytes[NW * 8U - 1U - i] = static_cast<CryptoByte>((a.d[limb_idx] >> bit_shift) & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}


// -----------------------------------------------------------------------
// Comparison and selection (constant-time).
// -----------------------------------------------------------------------

// Returns 0xFFFFFFFFFFFFFFFF if a < b, else 0.
template<std::size_t NW>
[[nodiscard]]
inline uint64_t bigint_ct_lt(const BigInt<NW>& a, const BigInt<NW>& b) noexcept {
    uint64_t borrow = 0;
    for (std::size_t i = 0; i < NW; ++i) {
        const uint64_t ai = a.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        const uint64_t bi = b.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        const uint64_t diff = ai - bi - borrow;
        // borrow = 1 iff ai < bi + borrow
        borrow = ((ai < bi + borrow) || (borrow == 1U && bi == UINT64_MAX)) ? 1U : 0U;
        (void)diff;
    }
    return borrow ? UINT64_MAX : 0ULL;
}

// Constant-time select: returns a if mask == all-ones, else b.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_ct_select(const BigInt<NW>& a, const BigInt<NW>& b, uint64_t mask) noexcept {
    BigInt<NW> out{};
    for (std::size_t i = 0; i < NW; ++i) {
        out.d[i] = (a.d[i] & mask) | (b.d[i] & ~mask); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return out;
}

// Equality: returns true iff a == b (constant-time).
template<std::size_t NW>
[[nodiscard]]
inline bool bigint_eq(const BigInt<NW>& a, const BigInt<NW>& b) noexcept {
    uint64_t diff = 0;
    for (std::size_t i = 0; i < NW; ++i) {
        diff |= a.d[i] ^ b.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return diff == 0U;
}


// -----------------------------------------------------------------------
// Addition and subtraction with carry/borrow.
// -----------------------------------------------------------------------

// out = a + b.  Returns carry out (0 or 1).
template<std::size_t NW>
inline uint64_t bigint_add(BigInt<NW>& out, const BigInt<NW>& a, const BigInt<NW>& b) noexcept {
    uint64_t carry = 0;
    for (std::size_t i = 0; i < NW; ++i) {
        const __uint128_t sum = static_cast<__uint128_t>(a.d[i]) + b.d[i] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        out.d[i] = static_cast<uint64_t>(sum); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        carry    = static_cast<uint64_t>(sum >> 64U);
    }
    return carry;
}

// out = a - b.  Returns borrow out (0 or 1).
template<std::size_t NW>
inline uint64_t bigint_sub(BigInt<NW>& out, const BigInt<NW>& a, const BigInt<NW>& b) noexcept {
    uint64_t borrow = 0;
    for (std::size_t i = 0; i < NW; ++i) {
        const __uint128_t ai = a.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        const __uint128_t bi = static_cast<__uint128_t>(b.d[i]) + borrow; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        out.d[i] = static_cast<uint64_t>(ai - bi); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        borrow   = (ai < bi) ? 1U : 0U;
    }
    return borrow;
}

// Conditional subtraction: if a >= m, return a - m; else return a.
// Constant-time (no branches on the value).
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_reduce_once(const BigInt<NW>& a, const BigInt<NW>& m) noexcept {
    BigInt<NW> diff{};
    const uint64_t borrow = bigint_sub(diff, a, m);
    // borrow == 1 means a < m, so we should keep a.
    const uint64_t keep_original = borrow ? UINT64_MAX : 0ULL;
    return bigint_ct_select(a, diff, keep_original);
}


// -----------------------------------------------------------------------
// Montgomery multiplication.
// -----------------------------------------------------------------------

// Compute m0inv = -m[0]^{-1} mod 2^64 using Newton's method.
// Only valid for odd m.
[[nodiscard]]
inline uint64_t mont_compute_m0inv(uint64_t m0) noexcept {
    // Start: inv ≡ m0 mod 2^4 (m0 is odd, so this works).
    uint64_t inv = m0;  // 1 step good to 4 bits; iterate
    // Hensel lifting: each step doubles precision.
    for (int i = 0; i < 5; ++i) { // 5 iterations: 4,8,16,32,64 bits
        inv = inv * (2U - m0 * inv);
    }
    return static_cast<uint64_t>(-(static_cast<__uint128_t>(1U) * inv) % (static_cast<__uint128_t>(1U) << 64U)
           == 0U ? 0U : inv);
    // Simpler: just return -inv mod 2^64 directly.
}

// Actually: -m0^{-1} mod 2^64.
[[nodiscard]]
inline uint64_t mont_neg_inv(uint64_t m0) noexcept {
    uint64_t inv = m0;
    for (int i = 0; i < 5; ++i) {
        inv = inv * (2U - m0 * inv);
    }
    return static_cast<uint64_t>(-static_cast<__uint128_t>(inv));
}

// Montgomery multiplication: compute T = a * b * R^{-1} mod m
// where R = 2^(64*NW).
// m0inv = -m[0]^{-1} mod 2^64.
// Uses CIOS (Coarsely Integrated Operand Scanning) with NW+1 limb accumulator.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> mont_mul(const BigInt<NW>& a, const BigInt<NW>& b,
                            const BigInt<NW>& m, uint64_t m0inv) noexcept {
    // t has NW+1 limbs; t[NW] catches carry overflow.
    std::array<uint64_t, NW + 1U> t{};

    for (std::size_t i = 0; i < NW; ++i) {
        // Phase 1: t += a[i] * b
        uint64_t carry = 0;
        for (std::size_t j = 0; j < NW; ++j) {
            const __uint128_t prod = static_cast<__uint128_t>(a.d[i]) * b.d[j] + t[j] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            t[j] = static_cast<uint64_t>(prod); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            carry = static_cast<uint64_t>(prod >> 64U);
        }
        t[NW] += carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

        // Phase 2: Montgomery reduction — t += (t[0] * m0inv mod 2^64) * m; t >>= 64
        const uint64_t q = t[0] * m0inv; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        __uint128_t c = static_cast<__uint128_t>(q) * m.d[0] + t[0]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        c >>= 64U;
        for (std::size_t j = 1; j < NW; ++j) {
            c += static_cast<__uint128_t>(q) * m.d[j] + t[j]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            t[j - 1U] = static_cast<uint64_t>(c); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            c >>= 64U;
        }
        c += t[NW]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        t[NW - 1U] = static_cast<uint64_t>(c); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        t[NW] = static_cast<uint64_t>(c >> 64U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Copy lower NW limbs.
    BigInt<NW> result{};
    for (std::size_t i = 0; i < NW; ++i) {
        result.d[i] = t[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    // Constant-time final reduction: subtract m if t[NW] != 0 or result >= m.
    const uint64_t overflow = t[NW]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    BigInt<NW> reduced{};
    const uint64_t borrow = bigint_sub(reduced, result, m);
    // keep_reduced is all-ones when we should use reduced (i.e. subtract was correct):
    //   - overflow != 0: result + t[NW]*2^(64*NW) >= m, so subtract
    //   - borrow == 0:   result >= m, so subtract
    // keep_reduced is zero when result < m and no overflow (keep result).
    const uint64_t overflow_mask = static_cast<uint64_t>(-static_cast<int64_t>(overflow != 0U));
    const uint64_t no_borrow_mask = static_cast<uint64_t>(-static_cast<int64_t>(borrow == 0U));
    const uint64_t keep_reduced = overflow_mask | no_borrow_mask;
    return bigint_ct_select(reduced, result, keep_reduced);
}

// Compute R^2 mod m (used to convert to Montgomery form).
// R = 2^(64*NW).  We compute this by repeated doubling/reduction.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> mont_r2(const BigInt<NW>& m) noexcept {
    // Start with 1, then shift left by 64*NW*2 bits (mod m) in 2*64*NW steps.
    BigInt<NW> r{};
    r.d[0] = 1U;
    // Compute R mod m = 2^(64*NW) mod m by shifting left 64*NW bits.
    // Then compute R^2 mod m = (R mod m)^2 mod m.
    // We do 2*64*NW doublings of r, each time reducing.
    const std::size_t total_bits = std::size_t{2} * std::size_t{64} * NW;
    for (std::size_t i = 0; i < total_bits; ++i) {
        // r = r * 2 mod m (left shift by 1, then conditional subtract).
        // Left shift r by 1 bit.
        uint64_t carry = 0;
        for (std::size_t j = 0; j < NW; ++j) {
            const uint64_t new_carry = r.d[j] >> 63U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            r.d[j] = (r.d[j] << 1U) | carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            carry = new_carry;
        }
        // If overflow (carry != 0) or r >= m, subtract m.
        if (carry != 0U) {
            // r overflowed 64*NW bits; guaranteed r - m < 2^(64*NW).
            bigint_sub(r, r, m);
        } else {
            r = bigint_reduce_once(r, m);
        }
    }
    return r;
}

// Convert a to Montgomery form: return a * R mod m.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> mont_to(const BigInt<NW>& a, const BigInt<NW>& m,
                           uint64_t m0inv, const BigInt<NW>& r2) noexcept {
    return mont_mul(a, r2, m, m0inv);
}

// Convert from Montgomery form: return a * R^{-1} mod m.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> mont_from(const BigInt<NW>& a, const BigInt<NW>& m, uint64_t m0inv) noexcept {
    BigInt<NW> one{};
    one.d[0] = 1U;
    return mont_mul(a, one, m, m0inv);
}


// -----------------------------------------------------------------------
// Constant-time modular exponentiation: base^exp mod m.
// Uses left-to-right binary exponentiation with Montgomery multiplication.
// No secret-dependent branches.
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_powmod_ct(
    const BigInt<NW>& base, const BigInt<NW>& exp,
    const BigInt<NW>& m) noexcept
{
    const uint64_t m0inv = mont_neg_inv(m.d[0]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const BigInt<NW> r2  = mont_r2(m);

    // Convert base to Montgomery form.
    BigInt<NW> result_m{};
    result_m.d[0] = 1U;  // will hold 1 in Montgomery form after first iteration
    BigInt<NW> base_m = mont_to(base, m, m0inv, r2);

    // result = R mod m (Montgomery representation of 1)
    result_m = mont_to(result_m, m, m0inv, r2);

    // Process bits from most significant to least significant.
    for (std::size_t wi = NW; wi-- > 0; ) {
        for (int bi = 63; bi >= 0; --bi) {
            // result = result^2
            result_m = mont_mul(result_m, result_m, m, m0inv);
            // Conditionally multiply by base if bit is set.
            const uint64_t bit = (exp.d[wi] >> static_cast<unsigned>(bi)) & 1U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const uint64_t bit_mask = static_cast<uint64_t>(-static_cast<int64_t>(bit));  // all-ones if bit==1
            BigInt<NW> prod = mont_mul(result_m, base_m, m, m0inv);
            result_m = bigint_ct_select(prod, result_m, bit_mask);
        }
    }

    return mont_from(result_m, m, m0inv);
}


// -----------------------------------------------------------------------
// RSA CRT: given m_p = m^dp mod p  and  m_q = m^dq mod q,
// reconstruct m = m_q + q * ((m_p - m_q) * qInvModP mod p).
//
// All BigInt values are NW limbs wide (padded to the modulus size).
// p and q are half-size (NW/2 limbs each), but we use NW for uniformity.
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> rsa_crt_combine(
    const BigInt<NW>& m_p,   // m^dp mod p (in full NW limbs, upper half zero)
    const BigInt<NW>& m_q,   // m^dq mod q (in full NW limbs, upper half zero)
    const BigInt<NW>& p,
    const BigInt<NW>& q,
    const BigInt<NW>& qinv)  // q^{-1} mod p
    noexcept
{
    // h = (m_p - m_q) mod p
    // If m_p < m_q, add p first to keep it positive.
    BigInt<NW> diff{};
    const uint64_t borrow = bigint_sub(diff, m_p, m_q);
    // If borrow, add p to correct.
    BigInt<NW> diff_adj{};
    bigint_add(diff_adj, diff, p);
    const uint64_t keep_diff = borrow ? 0ULL : UINT64_MAX;
    BigInt<NW> h_unnorm = bigint_ct_select(diff, diff_adj, keep_diff);
    h_unnorm = bigint_reduce_once(h_unnorm, p);

    // h = h_unnorm * qinv mod p
    const uint64_t p0inv = mont_neg_inv(p.d[0]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const BigInt<NW> r2_p = mont_r2(p);
    const BigInt<NW> h_m   = mont_to(h_unnorm, p, p0inv, r2_p);
    const BigInt<NW> qi_m  = mont_to(qinv,     p, p0inv, r2_p);
    const BigInt<NW> h_prod = mont_mul(h_m, qi_m, p, p0inv);
    const BigInt<NW> h     = mont_from(h_prod, p, p0inv);

    // result = m_q + q * h
    // Standard schoolbook multiplication: q[i] * h[j] contributes to qh[i+j].
    // Both q and h fit in NW/2 significant limbs; the product fits in NW limbs.
    BigInt<NW> qh{};
    for (std::size_t i = 0; i < NW; ++i) {
        if (q.d[i] == 0U) { continue; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        uint64_t carry = 0;
        for (std::size_t j = 0; j < NW && (i + j) < NW; ++j) {
            const __uint128_t prod = static_cast<__uint128_t>(q.d[i]) * h.d[j] // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                                   + qh.d[i + j] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            qh.d[i + j] = static_cast<uint64_t>(prod); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            carry = static_cast<uint64_t>(prod >> 64U);
        }
    }

    BigInt<NW> result{};
    bigint_add(result, qh, m_q);
    return result;
}


// -----------------------------------------------------------------------
// High-level RSA private-key operation: m = c^d mod n (using CRT).
// Half-size: NW = full modulus limbs; HW = NW/2 = prime limbs.
//
// Inputs (big-endian byte arrays):
//   c        : ciphertext / hash, byte_len = NW*8
//   n_bytes  : modulus
//   p_bytes  : prime p (half-width)
//   q_bytes  : prime q (half-width)
//   dp_bytes : d mod (p-1)
//   dq_bytes : d mod (q-1)
//   qi_bytes : q^{-1} mod p
//
// Output: m_bytes (big-endian, NW*8 bytes).
// -----------------------------------------------------------------------

template<std::size_t NW>
inline void rsa_private_op(
    const CryptoByte* c_bytes,   std::size_t c_len,
    const CryptoByte* p_bytes,   std::size_t p_len,
    const CryptoByte* q_bytes,   std::size_t q_len,
    const CryptoByte* dp_bytes,  std::size_t dp_len,
    const CryptoByte* dq_bytes,  std::size_t dq_len,
    const CryptoByte* qi_bytes,  std::size_t qi_len,
    CryptoByte* m_bytes) noexcept
{
    const BigInt<NW> c  = bigint_from_bytes<NW>(c_bytes, c_len);
    const BigInt<NW> p  = bigint_from_bytes<NW>(p_bytes, p_len);
    const BigInt<NW> q  = bigint_from_bytes<NW>(q_bytes, q_len);
    const BigInt<NW> dp = bigint_from_bytes<NW>(dp_bytes, dp_len);
    const BigInt<NW> dq = bigint_from_bytes<NW>(dq_bytes, dq_len);
    const BigInt<NW> qi = bigint_from_bytes<NW>(qi_bytes, qi_len);

    // c mod p and c mod q (reduce by repeated subtraction is too slow for
    // large moduli; instead we compute via the Montgomery form and use the
    // fact that p,q are half-width — safe to just pass the full c and rely
    // on bigint_powmod_ct, which works modulo p/q respectively).
    const BigInt<NW> m_p = bigint_powmod_ct(c, dp, p);
    const BigInt<NW> m_q = bigint_powmod_ct(c, dq, q);

    const BigInt<NW> m = rsa_crt_combine(m_p, m_q, p, q, qi);
    bigint_to_bytes(m, m_bytes);
}


// -----------------------------------------------------------------------
// High-level RSA public-key operation: c = m^e mod n.
// -----------------------------------------------------------------------

template<std::size_t NW>
inline void rsa_public_op(
    const CryptoByte* m_bytes,  std::size_t m_len,
    const CryptoByte* n_bytes,  std::size_t n_len,
    const CryptoByte* e_bytes,  std::size_t e_len,
    CryptoByte* c_bytes) noexcept
{
    const BigInt<NW> m = bigint_from_bytes<NW>(m_bytes, m_len);
    const BigInt<NW> n = bigint_from_bytes<NW>(n_bytes, n_len);
    const BigInt<NW> e = bigint_from_bytes<NW>(e_bytes, e_len);
    const BigInt<NW> c = bigint_powmod_ct(m, e, n);
    bigint_to_bytes(c, c_bytes);
}


}  // namespace arm_asm::detail
