// SPDX-License-Identifier: Apache-2.0

#pragma once

// CLI logging initialisation — wires spdlog to the safe-crypto-lib hook.
//
// Call cli_init_logging() from main() before subcommand dispatch.
//
// Without a config file the --log-level option controls verbosity; default
// is "warn" so normal CLI usage is silent.  Passing "off" disables all
// logging.
//
// With --log-config <path> a JSON file drives sink selection and level:
//
//   {
//     "level": "debug",
//     "sinks": [
//       { "type": "stderr" },
//       { "type": "file", "path": "/var/log/scli.log",
//         "max_size_mb": 10, "max_files": 3 }
//     ]
//   }
//
// If both --log-level and --log-config are supplied, --log-config wins.

#include <cstddef>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <nlohmann/json.hpp>

#include "crypto_log.hpp"


namespace scli {

namespace cli_logging_detail {

inline auto parse_level(const std::string& level_str) -> spdlog::level::level_enum
{
    if (level_str == "trace")    { return spdlog::level::trace;    }
    if (level_str == "debug")    { return spdlog::level::debug;    }
    if (level_str == "info")     { return spdlog::level::info;     }
    if (level_str == "warn")     { return spdlog::level::warn;     }
    if (level_str == "error")    { return spdlog::level::err;      }
    if (level_str == "critical") { return spdlog::level::critical; }
    if (level_str == "off")      { return spdlog::level::off;      }
    return spdlog::level::warn;
}

inline auto to_lib_threshold(spdlog::level::level_enum spdlog_level) -> CryptoLogLevel
{
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
}

inline void wire_lib_hook(spdlog::level::level_enum spdlog_level)
{
    const auto lib_threshold = to_lib_threshold(spdlog_level);
    if (lib_threshold == CryptoLogLevel::Off) {
        crypto_set_log_sink(nullptr);
        return;
    }
    crypto_set_log_sink(
        [](CryptoLogLevel level, std::string_view msg) {
            auto log = spdlog::get("scli");
            if (!log) { return; }
            switch (level) {
                case CryptoLogLevel::Debug: log->debug("{}", msg); break;
                case CryptoLogLevel::Info:  log->info("{}", msg);  break;
                case CryptoLogLevel::Warn:  log->warn("{}", msg);  break;
                case CryptoLogLevel::Error: log->error("{}", msg); break;
                default:                                            break;
            }
        },
        lib_threshold
    );
}

inline auto make_logger_from_json(const nlohmann::json& cfg)
    -> std::shared_ptr<spdlog::logger>
{
    constexpr std::size_t DEFAULT_MAX_SIZE_BYTES = 10ULL * 1024ULL * 1024ULL;
    constexpr std::size_t DEFAULT_MAX_FILES      = 3;
    constexpr std::size_t BYTES_PER_MB           = 1024ULL * 1024ULL;

    std::vector<spdlog::sink_ptr> sinks;

    if (cfg.contains("sinks")) {
        for (const auto& sink_cfg : cfg.at("sinks")) {
            const auto type = sink_cfg.value("type", "stderr");
            if (type == "stderr") {
                sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
            } else if (type == "stdout") {
                sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
            } else if (type == "file") {
                if (!sink_cfg.contains("path")) {
                    throw std::runtime_error("log-config: file sink requires \"path\"");
                }
                const std::string path = sink_cfg.at("path");
                const std::size_t max_size =
                    sink_cfg.value("max_size_mb", 10ULL) * BYTES_PER_MB;
                const std::size_t max_files =
                    sink_cfg.value("max_files", DEFAULT_MAX_FILES);
                sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    path, max_size > 0 ? max_size : DEFAULT_MAX_SIZE_BYTES,
                    max_files > 0 ? max_files : DEFAULT_MAX_FILES));
                // spdlog creates the file with the process umask; restrict to
                // owner-only because log output is a security-sensitive surface.
#ifndef _WIN32
                ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
            } else {
                throw std::runtime_error("log-config: unknown sink type \"" + type + "\"");
            }
        }
    }

    if (sinks.empty()) {
        sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    }

    return std::make_shared<spdlog::logger>("scli", sinks.begin(), sinks.end());
}

} // namespace cli_logging_detail


// Initialise logging from a level string alone (no config file).
inline void cli_init_logging(const std::string& level_str)
{
    auto logger = spdlog::get("scli");
    if (!logger) {
        logger = spdlog::stderr_color_mt("scli");
    }
    const auto spdlog_level = cli_logging_detail::parse_level(level_str);
    logger->set_level(spdlog_level);
    spdlog::set_default_logger(logger);
    cli_logging_detail::wire_lib_hook(spdlog_level);
}

// Initialise logging from a JSON config file.  level_str is used as a
// fallback when the file has no "level" key.
// Returns an empty string on success, or an error message on failure.
[[nodiscard]]
inline auto cli_init_logging_from_config(const std::string& config_path,
                                         const std::string& fallback_level = "warn")
    -> std::string
{
    nlohmann::json cfg;
    try {
        std::ifstream f(config_path);
        if (!f.is_open()) {
            return "log-config: cannot open \"" + config_path + "\"";
        }
        f >> cfg;
    } catch (const nlohmann::json::parse_error& ex) {
        return std::string("log-config: JSON parse error: ") + ex.what();
    }

    std::shared_ptr<spdlog::logger> logger;
    try {
        logger = cli_logging_detail::make_logger_from_json(cfg);
    } catch (const std::runtime_error& ex) {
        return std::string(ex.what());
    }

    const std::string level_str = cfg.value("level", fallback_level);
    const auto spdlog_level = cli_logging_detail::parse_level(level_str);
    logger->set_level(spdlog_level);

    spdlog::register_logger(logger);
    spdlog::set_default_logger(logger);
    cli_logging_detail::wire_lib_hook(spdlog_level);
    return {};
}

} // namespace scli
