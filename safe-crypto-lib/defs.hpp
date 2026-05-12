// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>


using CryptoByte = std::uint8_t;

// Template aliases for fixed-size byte arrays and spans.
// Prefer these over spelling out std::array<CryptoByte, N> or
// std::span<[const] CryptoByte, N> at every use site.
template<std::size_t N> using ByteArray = std::array<CryptoByte, N>;
template<std::size_t N> using ByteSpan  = std::span<CryptoByte, N>;
template<std::size_t N> using CByteSpan = std::span<const CryptoByte, N>;

constexpr std::size_t bits_per_byte = 8;

// AES-256
constexpr std::size_t aes256_key_size_bytes  = 32;
constexpr std::size_t aes256_key_bits        = aes256_key_size_bytes  * bits_per_byte;

// AES-256-GCM / ChaCha20-Poly1305 AEAD
constexpr std::size_t aes_gcm_tag_bytes              = 16;
constexpr std::size_t aes_gcm_nonce_bytes            = 12;
constexpr std::size_t chacha20_poly1305_tag_bytes     = 16;
constexpr std::size_t chacha20_poly1305_nonce_bytes   = 12;

// ChaCha20
constexpr std::size_t chacha20_block_bytes    = 64;
constexpr std::size_t chacha20_key_size_bytes = 32;
constexpr std::size_t chacha20_key_bits       = chacha20_key_size_bytes * bits_per_byte;

// Poly1305
constexpr std::size_t poly1305_key_bytes = 32;
constexpr std::size_t poly1305_tag_bytes = 16;

// SHA-2 block sizes
constexpr std::size_t sha256_block_bytes = 64;
constexpr std::size_t sha512_block_bytes = 128;

// SHA-2 internal structure constants
constexpr std::size_t sha256_state_words    =  8;  // number of 32-bit state words
constexpr std::size_t sha256_round_constants = 64;  // number of round constants (K[])
constexpr std::size_t sha512_state_words    =  8;  // number of 64-bit state words
constexpr std::size_t sha512_round_constants = 80;  // number of round constants (K[])

// SHA-2 digest output sizes
constexpr std::size_t sha256_digest_bytes = 32;
constexpr std::size_t sha384_digest_bytes = 48;
constexpr std::size_t sha512_digest_bytes = 64;

// SHA-3 digest output sizes
constexpr std::size_t sha3_256_digest_bytes = 32;
constexpr std::size_t sha3_384_digest_bytes = 48;
constexpr std::size_t sha3_512_digest_bytes = 64;

// EC curve bit widths
constexpr std::size_t p256_bits = 256;
constexpr std::size_t p384_bits = 384;
constexpr std::size_t p521_bits = 521;

// EC scalar (private key) sizes in bytes
constexpr std::size_t p256_scalar_bytes = 32;
constexpr std::size_t p384_scalar_bytes = 48;
constexpr std::size_t p521_scalar_bytes = 66;

// EC uncompressed public key sizes in bytes (0x04 prefix + 2 * scalar)
constexpr std::size_t p256_public_key_bytes = 65;
constexpr std::size_t p384_public_key_bytes = 97;
constexpr std::size_t p521_public_key_bytes = 133;

// ECDSA signature sizes in bytes (r ‖ s, each scalar-sized)
constexpr std::size_t p256_sig_bytes = 64;
constexpr std::size_t p384_sig_bytes = 96;
constexpr std::size_t p521_sig_bytes = 132;

// RSA modulus bit widths
constexpr std::size_t rsa_1024_bits = 1024;
constexpr std::size_t rsa_2048_bits = 2048;
constexpr std::size_t rsa_3072_bits = 3072;

// Miller-Rabin primality test rounds for RSA prime generation.
// Uses the FIPS 186-4/186-5 table values for the supported RSA prime sizes.
// For primes larger than the table, keep the 2048-bit-prime count rather than reducing rounds.
[[nodiscard]]
constexpr unsigned int miller_rabin_rounds_for(std::size_t prime_bits) noexcept {
    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // FIPS 186-4 Table C.1: minimum Miller-Rabin rounds by prime size.
    if (prime_bits >= 1345U) { return 4U; }
    if (prime_bits >=  476U) { return 5U; }
    if (prime_bits >=  400U) { return 6U; }
    if (prime_bits >=  347U) { return 7U; }
    if (prime_bits >=  308U) { return 8U; }
    return 27U;  // < 308 bits (small primes in tests)
    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

// HKDF-SHA-384 maximum output length: 255 * HashLen (RFC 5869 §2.3, HashLen=48)
constexpr std::size_t hkdf_sha384_max_output_bytes = 255U * sha384_digest_bytes;

// SHA padding start byte (0x80 appended after the message in SHA-1/2/3 padding).
constexpr CryptoByte sha_padding_marker = 0x80U;

// ASN.1/DER encoding constants.
constexpr CryptoByte der_sequence_tag = 0x30U;  // SEQUENCE tag
constexpr CryptoByte der_integer_tag  = 0x02U;  // INTEGER tag
constexpr CryptoByte der_msb_flag     = 0x80U;  // long-form length indicator / sign-bit test
constexpr CryptoByte der_two_byte_len = 0x82U;  // two-byte length prefix
constexpr CryptoByte der_one_byte_len = 0x81U;  // one-byte length prefix
constexpr CryptoByte der_ff_byte      = 0xFFU;  // all-bits-set byte (mask / upper byte)

// RSA/PKCS#1 constants.
constexpr CryptoByte rsa_pss_trailer  = 0xBCU;  // PKCS#1 PSS trailer field byte (RFC 8017 §9.1)
constexpr CryptoByte rsa_top_two_bits = 0xC0U;  // top-two-bits mask for RSA prime candidates

// P-521 field-element high-byte mask: only bit 0 is valid in the top byte of a
// 66-byte (528-bit) encoding of a 521-bit value; bits 7:1 must be zero.
constexpr CryptoByte p521_top_byte_mask = 0xFEU;

// Bits per 64-bit limb (for BigInt arithmetic).
constexpr std::size_t uint64_bits = 64U;

// Benchmark payload sizes
constexpr std::size_t bench_size_small  =     64;
constexpr std::size_t bench_size_medium =   1024;
constexpr std::size_t bench_size_large  =  16384;
constexpr std::size_t bench_size_xlarge = 262144;
