// SPDX-License-Identifier: Apache-2.0

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_logging.hpp"
#include "cmd_aead.hpp"
#include "cmd_digest.hpp"
#include "cmd_ecdh.hpp"
#include "cmd_ecdsa.hpp"
#include "cmd_kdf.hpp"
#include "cmd_mac.hpp"
#include "cmd_ml_dsa.hpp"
#include "cmd_ml_kem.hpp"
#include "cmd_random.hpp"
#include "cmd_rsa.hpp"
#include "cmd_slh_dsa.hpp"


namespace {

// Scan argv for --flag <value> or --flag=<value>, return value or "".
auto scan_argv_flag(int argc, char** argv, std::string_view flag) -> std::string  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    const std::string eq_prefix = std::string(flag) + "=";
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg.starts_with(eq_prefix)) {
            return std::string{arg.substr(eq_prefix.size())};
        }
        if (arg == flag && i + 1 < argc) {
            return std::string{argv[i + 1]};
        }
    }
    return {};
}

// Resolve logging configuration before CLI11 parses anything so that
// subcommand callbacks (which run inside CLI11_PARSE) already have a live
// logger.  --log-config wins over --log-level; falls back to SCLI_LOG_LEVEL
// env var, then to "warn".
void early_init_logging(int argc, char** argv)  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    const auto config_path = scan_argv_flag(argc, argv, "--log-config");
    if (!config_path.empty()) {
        // --log-config overrides --log-level; pass --log-level as fallback.
        const auto level_arg = scan_argv_flag(argc, argv, "--log-level");
        const auto fallback  = level_arg.empty() ? "warn" : level_arg;
        const auto err = scli::cli_init_logging_from_config(config_path, fallback);
        if (!err.empty()) {
            // Config file error: report to stderr and fall through to default.
            std::cerr << "Error: " << err << '\n';
        } else {
            return;
        }
    }

    auto level = scan_argv_flag(argc, argv, "--log-level");
    if (level.empty()) {
        if (const char* env = std::getenv("SCLI_LOG_LEVEL"); env != nullptr) {  // NOLINT(concurrency-mt-unsafe)
            level = std::string{env};
        }
    }
    scli::cli_init_logging(level.empty() ? "warn" : level);
}

} // namespace


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    early_init_logging(argc, argv);

    CLI::App app{"scli — safe-crypto-lib command line interface"};
    app.require_subcommand(1);

    std::string log_level = "warn";
    app.add_option("--log-level", log_level,
        "Log verbosity: trace, debug, info, warn, error, critical, off (default: warn)")
        ->envname("SCLI_LOG_LEVEL");

    std::string log_config;
    app.add_option("--log-config", log_config,
        "Path to JSON logging config file (overrides --log-level)");

    scli::register_aead(app);
    scli::register_digest(app);
    scli::register_ecdh(app);
    scli::register_ecdsa(app);
    scli::register_kdf(app);
    scli::register_mac(app);
    scli::register_ml_dsa(app);
    scli::register_ml_kem(app);
    scli::register_random(app);
    scli::register_rsa(app);
    scli::register_slh_dsa(app);

    if (argc == 1) {
        std::cout << app.help();
        return 0;
    }

    CLI11_PARSE(app, argc, argv);
    return 0;
}
