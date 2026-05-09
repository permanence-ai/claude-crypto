// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdlib>
#include <iostream>
#include <string_view>

#include "crypto_error.hpp"


namespace scli {

[[noreturn]]
inline void die(std::string_view msg)
{
    std::cerr << "Error: " << msg << '\n';
    std::exit(1);  // NOLINT(concurrency-mt-unsafe)
}

[[noreturn]]
inline void die(const CryptoError& err)
{
    std::cerr << "Error: " << err.message() << '\n';
    std::exit(1);  // NOLINT(concurrency-mt-unsafe)
}

}  // namespace scli
