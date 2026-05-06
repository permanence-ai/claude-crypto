// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// RSA key pair generation without third-party library dependencies.
//
// Algorithm overview:
//   1. Generate a random prime p of prime_bits bits (Miller-Rabin, 40 rounds).
//   2. Generate a random prime q of prime_bits bits, distinct from p.
//   3. Verify gcd(e, p-1) == 1 and gcd(e, q-1) == 1.
//   4. n = p * q.
//   5. phi = (p-1) * (q-1)  [uses (p-1)*(q-1) rather than lcm, valid for RSA].
//   6. d   = e^{-1} mod phi  (uses small-e shortcut — see below).
//   7. dp  = e^{-1} mod (p-1), dq = e^{-1} mod (q-1)  (same trick, half-size).
//   8. qinv = q^{-1} mod p   (Fermat: q^{p-2} mod p, since p is prime).
//   9. Encode as PKCS#1 RSAPrivateKey DER.
//
// Public exponent e = 65537 throughout.
//
// "Small-e shortcut" for d = e^{-1} mod m:
//   We want d in [0,m) s.t. e*d = 1 + k*m for some k in [0, e).
//   k ≡ -1 * (m mod e)^{-1}  (mod e).
//   Since e = 65537 is prime and small, (m mod e)^{-1} is computed via 32-bit arithmetic.
//   Then d = (k*m + 1) / e  via exact division.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "defs.hpp"
#include "random.hpp"
#include "rsa_bigint.hpp"
#include "rsa_der.hpp"


namespace arm_asm::detail {


constexpr uint64_t rsa_public_exponent = 65537U;


// -----------------------------------------------------------------------
// Utility: test if BigInt is zero.
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline bool bigint_is_zero(const BigInt<NW>& a) noexcept {
    uint64_t acc = 0;
    for (std::size_t i = 0; i < NW; ++i) { acc |= a.d[i]; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    return acc == 0U;
}

// Utility: test if BigInt is even (bit 0 == 0).
template<std::size_t NW>
[[nodiscard]]
inline bool bigint_is_even(const BigInt<NW>& a) noexcept {
    return (a.d[0] & 1U) == 0U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

// Utility: right shift by 1 bit.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_shr1(const BigInt<NW>& a) noexcept {
    BigInt<NW> r{};
    uint64_t carry = 0;
    for (std::size_t i = NW; i-- > 0U; ) {
        r.d[i] = (a.d[i] >> 1U) | (carry << 63U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        carry = a.d[i] & 1U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return r;
}

// Utility: subtract 1.  Precondition: a > 0.
template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> bigint_dec(const BigInt<NW>& a) noexcept {
    BigInt<NW> one{};  one.d[0] = 1U;
    BigInt<NW> r{};
    bigint_sub(r, a, one);
    return r;
}

// Utility: double (a * 2).  Returns overflow carry.
template<std::size_t NW>
inline uint64_t bigint_shl1(BigInt<NW>& out, const BigInt<NW>& a) noexcept {
    uint64_t carry = 0;
    for (std::size_t i = 0; i < NW; ++i) {
        const uint64_t new_carry = a.d[i] >> 63U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        out.d[i] = (a.d[i] << 1U) | carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        carry = new_carry;
    }
    return carry;
}


// -----------------------------------------------------------------------
// bigint_mod_small: compute A mod d for small d (fits in uint64_t).
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline uint64_t bigint_mod_small(const BigInt<NW>& a, uint64_t d) noexcept {
    __uint128_t rem = 0;
    for (std::size_t i = NW; i-- > 0U; ) {
        const __uint128_t val = (rem << 64U) | a.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        rem = val % d;
    }
    return static_cast<uint64_t>(rem);
}


// -----------------------------------------------------------------------
// small_modinv_u64: a^{-1} mod p for small prime p using Fermat.
// Returns 0 if a ≡ 0 (mod p).
// -----------------------------------------------------------------------

[[nodiscard]]
inline uint64_t small_modinv_u64(uint64_t a, uint64_t p) noexcept {
    // Fermat: a^{p-2} mod p (p is prime).
    if (a == 0U) { return 0U; }
    uint64_t result = 1U;
    uint64_t base = a % p;
    uint64_t exp = p - 2U;
    while (exp > 0U) {
        if ((exp & 1U) != 0U) {
            result = static_cast<uint64_t>((static_cast<__uint128_t>(result) * base) % p);
        }
        base = static_cast<uint64_t>((static_cast<__uint128_t>(base) * base) % p);
        exp >>= 1U;
    }
    return result;
}


// -----------------------------------------------------------------------
// small_e_modinv: compute e^{-1} mod m where e = rsa_public_exponent.
//
// Algorithm (see header comment):
//   r = m mod e
//   k = (e - r^{-1} mod e) % e    [so k*r ≡ -1 (mod e)]
//   num = k * m + 1                 [NW+1 limbs]
//   d = num / e                     [exact, since e | num]
//
// Returns zero BigInt<NW> if gcd(e, m) != 1 (i.e. e | m).
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> small_e_modinv(const BigInt<NW>& m) noexcept {
    const uint64_t e = rsa_public_exponent;

    // r = m mod e
    const uint64_t r = bigint_mod_small(m, e);
    if (r == 0U) { return BigInt<NW>{}; }  // e | m, no inverse

    // k = (-r^{-1}) mod e
    const uint64_t r_inv = small_modinv_u64(r, e);
    const uint64_t k = (e - r_inv) % e;  // k in [0, e-1]

    // num[0..NW] = k * m + 1  (NW+1 limbs, little-endian)
    std::array<uint64_t, NW + 1U> num{};
    uint64_t carry = 1U;  // +1
    for (std::size_t i = 0; i < NW; ++i) {
        const __uint128_t prod = static_cast<__uint128_t>(k) * m.d[i] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        num[i] = static_cast<uint64_t>(prod); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        carry = static_cast<uint64_t>(prod >> 64U);
    }
    num[NW] = carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

    // Exact division of num[0..NW] by e, from most-significant limb down.
    BigInt<NW> d{};
    uint64_t rem = 0U;
    {
        // Process the extra high limb (num[NW]).
        const __uint128_t val = (static_cast<__uint128_t>(rem) << 64U) | num[NW]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        rem = static_cast<uint64_t>(val % e);
        // The quotient for this position would go in d[NW], but d < m < 2^(64*NW), so it's 0.
    }
    for (std::size_t i = NW; i-- > 0U; ) {
        const __uint128_t val = (static_cast<__uint128_t>(rem) << 64U) | num[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        d.d[i] = static_cast<uint64_t>(val / e); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        rem = static_cast<uint64_t>(val % e);
    }
    // rem should be 0 (exact division by construction).
    return d;
}


// -----------------------------------------------------------------------
// Miller-Rabin primality test.
// Returns true if n is probably prime.
// Not constant-time (prime candidates are public during key generation).
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline bool miller_rabin_is_prime(const BigInt<NW>& n, unsigned int rounds) noexcept {
    // n must be > 3 and odd.
    // Write n-1 = 2^s * d  (d odd).
    const BigInt<NW> n_minus_1 = bigint_dec(n);
    BigInt<NW> d = n_minus_1;
    unsigned int s = 0;
    while (bigint_is_even(d)) {
        d = bigint_shr1(d);
        ++s;
    }
    if (s == 0U) { return false; }  // n-1 is odd means n is even

    for (unsigned int round = 0; round < rounds; ++round) {
        // Random witness a in [2, n-2].
        // Generate random bits, mask to fit in n's bit width, reduce mod (n-3), add 2.
        // Use Montgomery exponentiation to reduce: a = (random mod (n-3)) + 2.
        // For efficiency we compute a = bigint_powmod_ct trick: instead, just
        // mask the top limb to the same bit-count as n, then subtract n if a >= n.
        // This is O(NW) and correct as long as the masked value is in [0, 2*n).
        std::array<CryptoByte, NW * 8U> rand_buf{};
        generate_random_bytes(rand_buf.data(), rand_buf.size());
        BigInt<NW> a = bigint_from_bytes<NW>(rand_buf.data(), rand_buf.size());

        // Find the highest set bit of n to create a mask for a.
        // Count leading zeros of n's top nonzero limb.
        std::size_t top_limb = NW - 1U;
        while (top_limb > 0U && n.d[top_limb] == 0U) { --top_limb; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        const uint64_t top_val = n.d[top_limb]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        // Build a mask with all bits set up to and including the highest bit of top_val.
        std::size_t bit_pos = 63U;
        while (bit_pos > 0U && ((top_val >> bit_pos) & 1U) == 0U) { --bit_pos; }
        const uint64_t top_mask = (bit_pos == 63U) ? UINT64_MAX : ((UINT64_C(1) << (bit_pos + 1U)) - 1U);

        // Zero out limbs above top_limb; mask the top limb.
        for (std::size_t i = top_limb + 1U; i < NW; ++i) { a.d[i] = 0U; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        a.d[top_limb] &= top_mask; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

        // Now a is in [0, 2*n). Subtract n at most once to bring into [0, n).
        if (bigint_ct_lt(a, n) == 0U) {
            BigInt<NW> tmp{};
            bigint_sub(tmp, a, n);
            a = tmp;
        }

        // Clamp to [2, n-2].
        BigInt<NW> two{};  two.d[0] = 2U;
        if (bigint_ct_lt(a, two) == UINT64_MAX || bigint_is_zero(a)) { a = two; }
        if (bigint_eq(a, n_minus_1)) { a = bigint_dec(n_minus_1); }

        // x = a^d mod n.
        BigInt<NW> x = bigint_powmod_ct(a, d, n);

        BigInt<NW> one{};  one.d[0] = 1U;
        if (bigint_eq(x, one) || bigint_eq(x, n_minus_1)) { continue; }

        bool maybe_prime = false;
        for (unsigned int r = 1; r < s; ++r) {
            // x = x^2 mod n.
            x = bigint_powmod_ct(x, two, n);
            if (bigint_eq(x, n_minus_1)) { maybe_prime = true; break; }
        }
        if (!maybe_prime) { return false; }
    }
    return true;
}


// -----------------------------------------------------------------------
// generate_prime: random prime of exactly prime_bits bits (multiple of 64).
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline BigInt<NW> generate_prime(std::size_t prime_bits) noexcept {
    const std::size_t byte_len = prime_bits / 8U;
    for (;;) {
        std::array<CryptoByte, NW * 8U> buf{};
        generate_random_bytes(buf.data(), byte_len);
        buf[0] |= 0xC0U;                     // set top two bits (correct length, not too small)
        buf[byte_len - 1U] |= 0x01U;          // ensure odd

        const BigInt<NW> candidate = bigint_from_bytes<NW>(buf.data(), byte_len);

        // Quick sieve: reject if divisible by small primes.
        static constexpr std::array<uint32_t, 54U> small_primes = {
            3,   5,   7,  11,  13,  17,  19,  23,  29,  31,
           37,  41,  43,  47,  53,  59,  61,  67,  71,  73,
           79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
          131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
          181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
          239, 241, 251, 257
        };
        bool divisible = false;
        for (const uint32_t sp : small_primes) {
            if (bigint_mod_small(candidate, sp) == 0U) { divisible = true; break; }
        }
        if (divisible) { continue; }

        if (miller_rabin_is_prime(candidate, 40U)) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            return candidate;
        }
    }
}


// -----------------------------------------------------------------------
// DER encoding helpers.
// -----------------------------------------------------------------------

// Encode DER length field, returns bytes written.
inline std::size_t der_write_length(std::size_t len, CryptoByte* buf) noexcept {
    CryptoByte* w = buf;
    if (len < 0x80U) {
        *w++ = static_cast<CryptoByte>(len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    } else if (len < 0x100U) {
        *w++ = 0x81U; *w++ = static_cast<CryptoByte>(len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    } else if (len < 0x10000U) {
        *w++ = 0x82U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *w++ = static_cast<CryptoByte>(len >> 8U); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *w++ = static_cast<CryptoByte>(len & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    } else {
        *w++ = 0x83U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *w++ = static_cast<CryptoByte>((len >> 16U) & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *w++ = static_cast<CryptoByte>((len >>  8U) & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        *w++ = static_cast<CryptoByte>(len & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return static_cast<std::size_t>(w - buf);
}

// Encode a BigInt as a DER INTEGER (with leading 0x00 if top bit set).
// meaningful_bytes: how many bytes from the MSB end of the NW*8 representation to use.
template<std::size_t NW>
inline std::size_t der_encode_integer(
    const BigInt<NW>& val, std::size_t meaningful_bytes,
    CryptoByte* out) noexcept
{
    std::array<CryptoByte, NW * 8U> be{};
    bigint_to_bytes(val, be.data());
    // Source bytes occupy the last meaningful_bytes of the full NW*8 output.
    const CryptoByte* src = be.data() + (NW * 8U - meaningful_bytes); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // Strip leading zeros, keep at least one byte.
    std::size_t start = 0;
    while (start + 1U < meaningful_bytes && src[start] == 0U) { ++start; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const CryptoByte* v = src + start; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::size_t v_len = meaningful_bytes - start;

    const bool needs_pad = (v[0] & 0x80U) != 0U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const std::size_t content = v_len + (needs_pad ? 1U : 0U);

    CryptoByte* w = out;
    *w++ = 0x02U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    w += der_write_length(content, w); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (needs_pad) { *w++ = 0x00U; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(w, v, v_len);
    w += v_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return static_cast<std::size_t>(w - out);
}


// -----------------------------------------------------------------------
// rsa_generate_key_der: generate a key pair and write PKCS#1 DER.
//
// NW  = limbs for full modulus (n, d); HW = NW/2 = limbs for each prime.
// modulus_bits must equal NW * 64.
// -----------------------------------------------------------------------

template<std::size_t NW>
[[nodiscard]]
inline bool rsa_generate_key_der(
    std::size_t modulus_bits,
    CryptoByte* out_buf, std::size_t out_max, std::size_t* out_len) noexcept
{
    static_assert(NW % 2U == 0U, "NW must be even");
    constexpr std::size_t HW = NW / 2U;

    const std::size_t prime_bits  = modulus_bits / 2U;
    const std::size_t mod_bytes   = modulus_bits / 8U;
    const std::size_t prime_bytes = prime_bits / 8U;

    const uint64_t e = rsa_public_exponent;
    BigInt<NW> e_full{};
    e_full.d[0] = e;

    for (;;) {
        // 1. Generate primes p, q.
        const BigInt<HW> p = generate_prime<HW>(prime_bits);
        const BigInt<HW> q = generate_prime<HW>(prime_bits);

        // Ensure p != q.
        {
            uint64_t acc = 0;
            for (std::size_t i = 0; i < HW; ++i) { acc |= p.d[i] ^ q.d[i]; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            if (acc == 0U) { continue; }
        }

        // 2. p-1 and q-1.
        const BigInt<HW> p1 = bigint_dec(p);
        const BigInt<HW> q1 = bigint_dec(q);

        // 3. Check gcd(e, p-1) == 1 and gcd(e, q-1) == 1.
        // Since e = 65537 is prime, gcd(e, x) is 1 iff e does not divide x.
        if (bigint_mod_small(p1, e) == 0U) { continue; }
        if (bigint_mod_small(q1, e) == 0U) { continue; }

        // 4. n = p * q  (schoolbook, HW+HW → NW limbs).
        BigInt<NW> n{};
        for (std::size_t i = 0; i < HW; ++i) {
            if (p.d[i] == 0U) { continue; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            uint64_t carry = 0;
            for (std::size_t j = 0; j < HW; ++j) {
                const __uint128_t prod = static_cast<__uint128_t>(p.d[i]) * q.d[j] // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                                       + n.d[i + j] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                n.d[i + j] = static_cast<uint64_t>(prod); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                carry = static_cast<uint64_t>(prod >> 64U);
            }
            n.d[i + HW] += carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }

        // 5. phi = (p-1) * (q-1)  (schoolbook, HW+HW → NW limbs).
        BigInt<NW> phi{};
        for (std::size_t i = 0; i < HW; ++i) {
            if (p1.d[i] == 0U) { continue; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            uint64_t carry = 0;
            for (std::size_t j = 0; j < HW; ++j) {
                const __uint128_t prod = static_cast<__uint128_t>(p1.d[i]) * q1.d[j] // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                                       + phi.d[i + j] + carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                phi.d[i + j] = static_cast<uint64_t>(prod); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                carry = static_cast<uint64_t>(prod >> 64U);
            }
            phi.d[i + HW] += carry; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }

        // 6. d = e^{-1} mod phi.
        const BigInt<NW> d = small_e_modinv(phi);
        if (bigint_is_zero(d)) { continue; }

        // 7. dp = e^{-1} mod (p-1), dq = e^{-1} mod (q-1).
        const BigInt<HW> dp = small_e_modinv(p1);
        if (bigint_is_zero(dp)) { continue; }
        const BigInt<HW> dq = small_e_modinv(q1);
        if (bigint_is_zero(dq)) { continue; }

        // 8. qinv = q^{-1} mod p  via Fermat: q^{p-2} mod p.
        const BigInt<HW> p_minus_2 = bigint_dec(p1);  // p-2 = (p-1)-1
        const BigInt<HW> qinv = bigint_powmod_ct(q, p_minus_2, p);
        if (bigint_is_zero(qinv)) { continue; }

        // 9. Encode PKCS#1 RSAPrivateKey DER.
        // Max body size: 9 integers, each up to mod_bytes+6 bytes, plus 3-byte sequence header.
        // version(3) + n,e,d overhead + p,q,dp,dq,qinv overhead
        const std::size_t max_body = 3U
            + 3U * (mod_bytes + 6U)    // n, e (3 bytes), d
            + 5U * (prime_bytes + 6U); // p, q, dp, dq, qinv
        const std::size_t hdr_reserve = 5U;
        if (out_max < max_body + hdr_reserve) { return false; }

        CryptoByte* body = out_buf + hdr_reserve;  // leave space for SEQUENCE header
        std::size_t body_len = 0;

        // version = 0
        body[body_len++] = 0x02U;
        body[body_len++] = 0x01U;
        body[body_len++] = 0x00U;

        // n, e (NW limbs → mod_bytes)
        body_len += der_encode_integer(n, mod_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_len += der_encode_integer(e_full, 3U, body + body_len);   // e = 0x010001 (3 bytes) // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        // d (NW limbs → mod_bytes)
        body_len += der_encode_integer(d, mod_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        // Promote HW → NW for p, q, dp, dq, qinv.
        BigInt<NW> p_nw{}, q_nw{}, dp_nw{}, dq_nw{}, qinv_nw{};
        for (std::size_t i = 0; i < HW; ++i) {
            p_nw.d[i]    = p.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            q_nw.d[i]    = q.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            dp_nw.d[i]   = dp.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            dq_nw.d[i]   = dq.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            qinv_nw.d[i] = qinv.d[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }

        body_len += der_encode_integer(p_nw,    prime_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_len += der_encode_integer(q_nw,    prime_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_len += der_encode_integer(dp_nw,   prime_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_len += der_encode_integer(dq_nw,   prime_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_len += der_encode_integer(qinv_nw, prime_bytes, body + body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        // Write SEQUENCE header into the reserved hdr_reserve bytes.
        CryptoByte hdr[5]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        hdr[0] = 0x30U;
        const std::size_t len_bytes = der_write_length(body_len, hdr + 1U);
        const std::size_t hdr_len = 1U + len_bytes;
        if (hdr_len > hdr_reserve) { return false; }  // shouldn't happen

        // Move body down to close the gap.
        const std::size_t gap = hdr_reserve - hdr_len;
        if (gap > 0U) {
            std::memmove(out_buf + hdr_len, out_buf + hdr_reserve, body_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
        std::memcpy(out_buf, hdr, hdr_len);
        *out_len = hdr_len + body_len;
        return true;
    }
}


}  // namespace arm_asm::detail
