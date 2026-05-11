// SPDX-License-Identifier: Apache-2.0

#pragma once

// Minimal DER parser and encoder for RSA keys.
//
// Supported formats:
//   Private key: PKCS#1 RSAPrivateKey (RFC 3447)
//     SEQUENCE {
//       INTEGER version (0),
//       INTEGER n, INTEGER e, INTEGER d,
//       INTEGER p, INTEGER q, INTEGER dp, INTEGER dq, INTEGER qinv
//     }
//
//   Public key: SubjectPublicKeyInfo (RFC 5480)
//     SEQUENCE {
//       SEQUENCE {
//         OID rsaEncryption (1.2.840.113549.1.1.1),
//         NULL
//       },
//       BIT STRING {
//         SEQUENCE { INTEGER n, INTEGER e }  -- RSAPublicKey
//       }
//     }
//
// All integers are stored big-endian with a possible leading 0x00 byte (to
// keep the DER INTEGER tag's sign bit clear).  The parser strips that byte
// before handing the value to the caller.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace arm_asm::detail {


// Up to 512 bytes for a 4096-bit integer (512 bytes + possible 0x00 prefix).
constexpr std::size_t rsa_max_int_bytes = 513;

// Maximum number of bits supported.
constexpr std::size_t rsa_max_key_bits  = 4096;
constexpr std::size_t rsa_max_key_bytes = rsa_max_key_bits / 8;  // 512


// -----------------------------------------------------------------------
// Parsed RSA private key (all values stripped of DER padding).
// -----------------------------------------------------------------------

struct RsaPrivateKeyComponents {
    const CryptoByte* n;   std::size_t n_len;
    const CryptoByte* e;   std::size_t e_len;
    const CryptoByte* d;   std::size_t d_len;
    const CryptoByte* p;   std::size_t p_len;
    const CryptoByte* q;   std::size_t q_len;
    const CryptoByte* dp;  std::size_t dp_len;
    const CryptoByte* dq;  std::size_t dq_len;
    const CryptoByte* qinv; std::size_t qinv_len;
};

struct RsaPublicKeyComponents {
    const CryptoByte* n;  std::size_t n_len;
    const CryptoByte* e;  std::size_t e_len;
};


// -----------------------------------------------------------------------
// Internal DER read helpers — operate on a cursor (ptr + remaining bytes).
// -----------------------------------------------------------------------

namespace der {

// Returns false if the tag doesn't match.
[[nodiscard]]
inline bool read_tag(const CryptoByte*& p, std::size_t& rem, uint8_t expected_tag) noexcept {
    if (rem < 1 || *p != expected_tag) { return false; }
    ++p; --rem;
    return true;
}

// Reads a DER length field.  Supports both short and long form.
// Returns false on malformed input or if the remaining bytes are insufficient.
[[nodiscard]]
inline bool read_length(const CryptoByte*& p, std::size_t& rem, std::size_t& out_len) noexcept {
    if (rem < 1) { return false; }
    const uint8_t first = *p; ++p; --rem;
    if ((first & 0x80U) == 0U) {
        out_len = first;
    } else {
        const std::size_t num_bytes = first & 0x7FU;
        if (num_bytes == 0 || num_bytes > 4 || rem < num_bytes) { return false; }
        out_len = 0;
        for (std::size_t i = 0; i < num_bytes; ++i) {
            out_len = (out_len << 8U) | static_cast<std::size_t>(*p);
            ++p; --rem;
        }
    }
    if (out_len > rem) { return false; }
    return true;
}

// Reads a SEQUENCE tag and length, advancing p into the SEQUENCE body.
// After this call, rem is the number of bytes within the sequence body.
[[nodiscard]]
inline bool enter_sequence(const CryptoByte*& p, std::size_t& rem) noexcept {
    if (!read_tag(p, rem, 0x30U)) { return false; }
    std::size_t seq_len = 0; // NOLINT(misc-const-correctness)
    if (!read_length(p, rem, seq_len)) { return false; }
    rem = seq_len;
    return true;
}

// Reads a DER INTEGER, stripping leading 0x00 padding byte if present.
// out_ptr points into the original buffer (no copy); out_len is the meaningful length.
[[nodiscard]]
inline bool read_integer(const CryptoByte*& p, std::size_t& rem,
                          const CryptoByte*& out_ptr, std::size_t& out_len) noexcept {
    if (!read_tag(p, rem, 0x02U)) { return false; }
    std::size_t int_len = 0;
    if (!read_length(p, rem, int_len)) { return false; }
    if (int_len == 0 || int_len > rsa_max_int_bytes) { return false; }
    // Strip optional leading 0x00 byte.
    const CryptoByte* val = p;
    std::size_t val_len = int_len;
    if (val_len > 1 && val[0] == 0x00U) { ++val; --val_len; }
    out_ptr = val;
    out_len = val_len;
    p   += int_len;
    rem -= int_len;
    return true;
}

// Skips an OID tag+length+value.
[[nodiscard]]
inline bool skip_oid(const CryptoByte*& p, std::size_t& rem) noexcept {
    if (!read_tag(p, rem, 0x06U)) { return false; }
    std::size_t oid_len = 0;
    if (!read_length(p, rem, oid_len)) { return false; }
    if (oid_len > rem) { return false; }
    p   += oid_len;
    rem -= oid_len;
    return true;
}

// Skips any TLV (tag, length, value) — used to skip NULL and optional params.
[[nodiscard]]
inline bool skip_tlv(const CryptoByte*& p, std::size_t& rem) noexcept {
    if (rem < 2) { return false; }
    ++p; --rem;  // skip tag
    std::size_t skip_len = 0;
    if (!read_length(p, rem, skip_len)) { return false; }
    if (skip_len > rem) { return false; }
    p   += skip_len;
    rem -= skip_len;
    return true;
}

// Reads a BIT STRING tag and length, and discards the leading "unused bits"
// byte (always 0x00 for key material), advancing into the bit string body.
[[nodiscard]]
inline bool enter_bit_string(const CryptoByte*& p, std::size_t& rem) noexcept {
    if (!read_tag(p, rem, 0x03U)) { return false; }
    std::size_t bs_len = 0; // NOLINT(misc-const-correctness)
    if (!read_length(p, rem, bs_len)) { return false; }
    if (bs_len < 1 || bs_len > rem) { return false; }
    // First byte of bit string content is "unused bits count" — must be 0.
    if (*p != 0x00U) { return false; }
    ++p; --rem;
    rem = bs_len - 1;
    return true;
}

}  // namespace der


// -----------------------------------------------------------------------
// Parse PKCS#1 RSAPrivateKey DER into components.
//
// All pointers in 'out' point into the original 'der_buf' buffer.
// Does not copy any data.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_parse_private_key_der(
    const CryptoByte* der_buf, std::size_t der_len,
    RsaPrivateKeyComponents& out) noexcept
{
    const CryptoByte* p   = der_buf;
    std::size_t       rem = der_len;

    if (!der::enter_sequence(p, rem)) { return false; }

    // version INTEGER (must be 0 for two-prime keys)
    const CryptoByte* ver_ptr = nullptr;
    std::size_t       ver_len = 0;
    if (!der::read_integer(p, rem, ver_ptr, ver_len)) { return false; }
    if (ver_len != 1 || ver_ptr[0] != 0x00U) { return false; }

    if (!der::read_integer(p, rem, out.n,    out.n_len))    { return false; }
    if (!der::read_integer(p, rem, out.e,    out.e_len))    { return false; }
    if (!der::read_integer(p, rem, out.d,    out.d_len))    { return false; }
    if (!der::read_integer(p, rem, out.p,    out.p_len))    { return false; }
    if (!der::read_integer(p, rem, out.q,    out.q_len))    { return false; }
    if (!der::read_integer(p, rem, out.dp,   out.dp_len))   { return false; }
    if (!der::read_integer(p, rem, out.dq,   out.dq_len))   { return false; }
    if (!der::read_integer(p, rem, out.qinv, out.qinv_len)) { return false; }

    return true;
}


// -----------------------------------------------------------------------
// Parse SubjectPublicKeyInfo DER into (n, e).
//
// All pointers in 'out' point into the original 'der_buf' buffer.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_parse_public_key_der(
    const CryptoByte* der_buf, std::size_t der_len,
    RsaPublicKeyComponents& out) noexcept
{
    const CryptoByte* p   = der_buf;
    std::size_t       rem = der_len;

    // Outer SEQUENCE
    if (!der::enter_sequence(p, rem)) { return false; }

    // Detect format by examining first byte of the SEQUENCE body:
    //   0x30 (SEQUENCE) → SubjectPublicKeyInfo (SPKI)
    //   0x02 (INTEGER)  → PKCS#1 RSAPublicKey
    if (rem < 1) { return false; }
    if (p[0] == 0x02U) {
        // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        if (!der::read_integer(p, rem, out.n, out.n_len)) { return false; }
        if (!der::read_integer(p, rem, out.e, out.e_len)) { return false; }
        return true;
    }

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
    // AlgorithmIdentifier SEQUENCE
    {
        if (rem < 2) { return false; }
        const CryptoByte* seq_p = p;
        std::size_t seq_rem = rem;
        if (!der::enter_sequence(seq_p, seq_rem)) { return false; }
        // OID rsaEncryption
        if (!der::skip_oid(seq_p, seq_rem)) { return false; }
        // NULL (optional parameters — mbedtls always writes it)
        if (seq_rem > 0) {
            if (!der::skip_tlv(seq_p, seq_rem)) { return false; }
        }
        // Advance outer cursor past the AlgorithmIdentifier.
        const CryptoByte* tmp_p = p;
        std::size_t tmp_rem = rem;
        ++tmp_p; --tmp_rem;  // skip 0x30 tag
        std::size_t algid_body_len = 0;
        if (!der::read_length(tmp_p, tmp_rem, algid_body_len)) { return false; }
        const std::size_t algid_total = static_cast<std::size_t>(tmp_p - p) + algid_body_len;
        if (algid_total > rem) { return false; }
        p   += algid_total;
        rem -= algid_total;
    }

    // BIT STRING containing RSAPublicKey
    if (!der::enter_bit_string(p, rem)) { return false; }

    // Inner SEQUENCE (RSAPublicKey)
    if (!der::enter_sequence(p, rem)) { return false; }

    if (!der::read_integer(p, rem, out.n, out.n_len)) { return false; }
    if (!der::read_integer(p, rem, out.e, out.e_len)) { return false; }

    return true;
}


// -----------------------------------------------------------------------
// Encode a SubjectPublicKeyInfo DER from (n, e).
//
// Writes into out_buf[0..out_len-1].  Returns false if buf is too small.
// n_bytes and e_bytes are big-endian, without leading zeros.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_encode_public_key_der( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* n_bytes, std::size_t n_len,
    const CryptoByte* e_bytes, std::size_t e_len,
    CryptoByte* out_buf, std::size_t out_max, std::size_t* out_len) noexcept
{
    // Fixed rsaEncryption OID: 1.2.840.113549.1.1.1
    static constexpr ByteArray<11> kRsaOid = {
        0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
    };
    static constexpr ByteArray<2> kNull = { 0x05, 0x00 };

    // Helper: encode a DER length into a local buffer, return bytes written.
    auto encode_len = [](std::size_t len, CryptoByte* buf) -> std::size_t {
        if (len < 0x80U) {
            buf[0] = static_cast<CryptoByte>(len);
            return 1;
        }
        if (len < 0x100U) {
            buf[0] = 0x81U;
            buf[1] = static_cast<CryptoByte>(len);
            return 2;
        }
        buf[0] = 0x82U;
        buf[1] = static_cast<CryptoByte>(len >> 8U);
        buf[2] = static_cast<CryptoByte>(len & 0xFFU);
        return 3;
    };

    // Determine whether we need a leading 0x00 byte for n and e.
    const bool n_needs_pad = (n_len > 0) && ((n_bytes[0] & 0x80U) != 0U);
    const bool e_needs_pad = (e_len > 0) && ((e_bytes[0] & 0x80U) != 0U);

    const std::size_t n_int_content = n_len + (n_needs_pad ? 1U : 0U);
    const std::size_t e_int_content = e_len + (e_needs_pad ? 1U : 0U);

    // INTEGER TLV sizes: tag(1) + len_field + content
    ByteArray<3> n_len_buf{};
    ByteArray<3> e_len_buf{};
    const std::size_t n_len_bytes = encode_len(n_int_content, n_len_buf.data());
    const std::size_t e_len_bytes = encode_len(e_int_content, e_len_buf.data());
    const std::size_t n_tlv = 1U + n_len_bytes + n_int_content;
    const std::size_t e_tlv = 1U + e_len_bytes + e_int_content;

    // Inner RSAPublicKey SEQUENCE body = n_tlv + e_tlv
    const std::size_t rsakey_body = n_tlv + e_tlv;
    ByteArray<3> rsakey_len_buf{};
    const std::size_t rsakey_len_bytes = encode_len(rsakey_body, rsakey_len_buf.data());
    const std::size_t rsakey_seq = 1U + rsakey_len_bytes + rsakey_body;

    // BIT STRING: 0x03, len, 0x00 (unused bits), RSAPublicKey SEQUENCE
    const std::size_t bitstr_content = 1U + rsakey_seq;
    ByteArray<3> bitstr_len_buf{};
    const std::size_t bitstr_len_bytes = encode_len(bitstr_content, bitstr_len_buf.data());
    const std::size_t bitstr_tlv = 1U + bitstr_len_bytes + bitstr_content;

    // AlgorithmIdentifier SEQUENCE = oid + null
    const std::size_t algid_body = kRsaOid.size() + kNull.size();
    ByteArray<3> algid_len_buf{};
    const std::size_t algid_len_bytes = encode_len(algid_body, algid_len_buf.data());
    const std::size_t algid_seq = 1U + algid_len_bytes + algid_body;

    // Outer SubjectPublicKeyInfo SEQUENCE body = algid + bitstr
    const std::size_t spki_body = algid_seq + bitstr_tlv;
    ByteArray<3> spki_len_buf{};
    const std::size_t spki_len_bytes = encode_len(spki_body, spki_len_buf.data());
    const std::size_t spki_total = 1U + spki_len_bytes + spki_body;

    if (spki_total > out_max) { return false; }

    CryptoByte* w = out_buf;
    auto write = [&](const CryptoByte* src, std::size_t n) {
        std::memcpy(w, src, n);
        w += n;
    };
    auto write_byte = [&](uint8_t b) { *w++ = b; };

    // Outer SEQUENCE
    write_byte(0x30U);
    write(spki_len_buf.data(), spki_len_bytes);

    // AlgorithmIdentifier SEQUENCE
    write_byte(0x30U);
    write(algid_len_buf.data(), algid_len_bytes);
    write(kRsaOid.data(), kRsaOid.size());
    write(kNull.data(),   kNull.size());

    // BIT STRING
    write_byte(0x03U);
    write(bitstr_len_buf.data(), bitstr_len_bytes);
    write_byte(0x00U);  // unused bits = 0

    // RSAPublicKey SEQUENCE
    write_byte(0x30U);
    write(rsakey_len_buf.data(), rsakey_len_bytes);

    // INTEGER n
    write_byte(0x02U);
    write(n_len_buf.data(), n_len_bytes);
    if (n_needs_pad) { write_byte(0x00U); }
    write(n_bytes, n_len);

    // INTEGER e
    write_byte(0x02U);
    write(e_len_buf.data(), e_len_bytes);
    if (e_needs_pad) { write_byte(0x00U); }
    write(e_bytes, e_len);

    *out_len = spki_total;
    return true;
}


// -----------------------------------------------------------------------
// Extract the public key (n, e) from a PKCS#1 private key DER and encode
// it as SubjectPublicKeyInfo DER.  Convenience wrapper for export_public_key.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_derive_public_key_der(
    const CryptoByte* priv_der, std::size_t priv_len,
    CryptoByte* out_buf, std::size_t out_max, std::size_t* out_len) noexcept
{
    RsaPrivateKeyComponents priv{};
    if (!rsa_parse_private_key_der(priv_der, priv_len, priv)) { return false; }
    return rsa_encode_public_key_der(
        priv.n, priv.n_len, priv.e, priv.e_len,
        out_buf, out_max, out_len);
}


// -----------------------------------------------------------------------
// Encode a PKCS#1 RSAPublicKey DER: SEQUENCE { INTEGER n, INTEGER e }.
// This is the format expected by PSA/mbedtls for PSA_KEY_TYPE_RSA_PUBLIC_KEY.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_encode_pkcs1_pubkey_der( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* n_bytes, std::size_t n_len,
    const CryptoByte* e_bytes, std::size_t e_len,
    CryptoByte* out_buf, std::size_t out_max, std::size_t* out_len) noexcept
{
    auto encode_len = [](std::size_t len, CryptoByte* buf) -> std::size_t {
        if (len < 0x80U) { buf[0] = static_cast<CryptoByte>(len); return 1; }
        if (len < 0x100U) { buf[0] = 0x81U; buf[1] = static_cast<CryptoByte>(len); return 2; }
        buf[0] = 0x82U;
        buf[1] = static_cast<CryptoByte>(len >> 8U);
        buf[2] = static_cast<CryptoByte>(len & 0xFFU);
        return 3;
    };

    const bool n_pad = (n_len > 0) && ((n_bytes[0] & 0x80U) != 0U);
    const bool e_pad = (e_len > 0) && ((e_bytes[0] & 0x80U) != 0U);
    const std::size_t nc = n_len + (n_pad ? 1U : 0U);
    const std::size_t ec = e_len + (e_pad ? 1U : 0U);

    ByteArray<3> nlen_buf{};
    ByteArray<3> elen_buf{};
    const std::size_t nlb = encode_len(nc, nlen_buf.data());
    const std::size_t elb = encode_len(ec, elen_buf.data());
    const std::size_t body = 1U + nlb + nc + 1U + elb + ec;

    ByteArray<3> slen_buf{};
    const std::size_t slb = encode_len(body, slen_buf.data());
    const std::size_t total = 1U + slb + body;

    if (total > out_max) { return false; }

    CryptoByte* w = out_buf;
    auto wb = [&](uint8_t b) { *w++ = b; };
    auto wn = [&](const CryptoByte* src, std::size_t n2) { std::memcpy(w, src, n2); w += n2; };

    wb(0x30U); wn(slen_buf.data(), slb);
    wb(0x02U); wn(nlen_buf.data(), nlb);
    if (n_pad) { wb(0x00U); }
    wn(n_bytes, n_len);
    wb(0x02U); wn(elen_buf.data(), elb);
    if (e_pad) { wb(0x00U); }
    wn(e_bytes, e_len);

    *out_len = total;
    return true;
}


}  // namespace arm_asm::detail
