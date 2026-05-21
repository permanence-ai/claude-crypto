// SPDX-License-Identifier: Apache-2.0

#pragma once

// CLI logging initialisation — wires spdlog to the safe-crypto-lib hook.
//
// Call cli_init_logging() from main() before subcommand dispatch.
// The --log-level option controls verbosity; default is "warn" so normal
// CLI usage is silent.  Passing "off" disables all logging.
//
// The library hook (crypto_set_log_sink) is fed a lambda that forwards
// every library log event into the "scli" spdlog logger.

#include <string>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "crypto_log.hpp"


namespace scli {

// Map a CLI level string to both spdlog and CryptoLogLevel thresholds.
// Accepted values (case-insensitive): trace, debug, info, warn, error, critical, off.
// Unknown strings are treated as "warn".
inline void cli_init_logging(const std::string& level_str)
{
    // Build a named stderr-colour logger (or reuse it if already created).
    auto logger = spdlog::get("scli");
    if (!logger) {
        logger = spdlog::stderr_color_mt("scli");
    }

    // Parse level string → spdlog level.
    const auto spdlog_level = [&]() -> spdlog::level::level_enum {
        if (level_str == "trace")    { return spdlog::level::trace;    }
        if (level_str == "debug")    { return spdlog::level::debug;    }
        if (level_str == "info")     { return spdlog::level::info;     }
        if (level_str == "warn")     { return spdlog::level::warn;     }
        if (level_str == "error")    { return spdlog::level::err;      }
        if (level_str == "critical") { return spdlog::level::critical; }
        if (level_str == "off")      { return spdlog::level::off;      }
        return spdlog::level::warn;
    }();

    logger->set_level(spdlog_level);
    spdlog::set_default_logger(logger);

    // Map spdlog level → CryptoLogLevel threshold for the library hook.
    const auto lib_threshold = [&]() -> CryptoLogLevel {
        switch (spdlog_level) {
            case spdlog::level::trace:
            case spdlog::level::debug:    return CryptoLogLevel::Debug;
            case spdlog::level::info:     return CryptoLogLevel::Info;
            case spdlog::level::warn:     return CryptoLogLevel::Warn;
            case spdlog::level::err:
            case spdlog::level::critical: return CryptoLogLevel::Error;
            case spdlog::level::off:
            default:                      return CryptoLogLevel::Off;
        }
    }();

    if (lib_threshold == CryptoLogLevel::Off) {
        // Disable the library hook entirely.
        crypto_set_log_sink(nullptr);
        return;
    }

    // Register a sink that forwards library events into the spdlog logger.
    crypto_set_log_sink(
        [](CryptoLogLevel level, std::string_view msg) {
            auto log = spdlog::get("scli");
            if (!log) { return; }
            switch (level) {
                case CryptoLogLevel::Debug: log->debug("{}", msg);    break;
                case CryptoLogLevel::Info:  log->info("{}", msg);     break;
                case CryptoLogLevel::Warn:  log->warn("{}", msg);     break;
                case CryptoLogLevel::Error: log->error("{}", msg);    break;
                default:                                               break;
            }
        },
        lib_threshold
    );
}

} // namespace scli
