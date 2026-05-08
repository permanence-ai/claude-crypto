// SPDX-License-Identifier: Apache-2.0

#pragma once

// Cryptographically secure random bytes for the ARM ASM backend.
// Uses arc4random_buf(3) which is available on macOS, iOS, and other Apple
// platforms.  arc4random_buf is seeded from the OS CSPRNG (getrandom / Secure
// Enclave / hardware RNG), is thread-safe, and never blocks.

#include <cstddef>
#include <cstdlib>

#include "defs.hpp"


namespace arm_asm::detail {

inline void generate_random_bytes(CryptoByte* buf, std::size_t len) noexcept {
    arc4random_buf(buf, len);
}

}  // namespace arm_asm::detail
