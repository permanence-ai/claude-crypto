// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>

#include "crypto_error.hpp"


namespace scli {

[[noreturn]]
inline void die(std::string_view msg)
{
    // Always write to stderr — fatal errors must be visible regardless of
    // --log-level (including "off").  Route through spdlog too when the logger
    // exists so the message gets the same formatting and any registered sinks.
    std::cerr << "Error: " << msg << '\n';
    const auto logger = spdlog::get("scli");
    if (logger) {
        logger->error("{}", msg);
        logger->flush();
    }
    std::exit(1);  // NOLINT(concurrency-mt-unsafe)
}

[[noreturn]]
inline void die(const CryptoError& err)
{
    die(std::string_view{err.message()});
}

}  // namespace scli
