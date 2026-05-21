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
    // Use spdlog when the logger will actually emit error-level messages;
    // otherwise fall back to std::cerr.  This avoids duplicate output at
    // normal log levels while still guaranteeing visibility at --log-level off.
    const auto logger = spdlog::get("scli");
    if (logger && logger->should_log(spdlog::level::err)) {
        logger->error("{}", msg);
        logger->flush();
    } else {
        std::cerr << "Error: " << msg << '\n';
    }
    std::exit(1);  // NOLINT(concurrency-mt-unsafe)
}

[[noreturn]]
inline void die(const CryptoError& err)
{
    die(std::string_view{err.message()});
}

}  // namespace scli
