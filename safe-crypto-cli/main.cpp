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


// Scan argv for --log-level <value> or --log-level=<value> before CLI11 parses
// anything.  This ensures subcommand callbacks (which run inside CLI11_PARSE)
// already have a live logger when they execute.  Falls back to SCLI_LOG_LEVEL
// env var, then to "warn" if neither is present.
static auto early_log_level(int argc, char** argv) -> std::string  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg.starts_with("--log-level=")) {
            return std::string{arg.substr(std::strlen("--log-level="))};
        }
        if (arg == "--log-level" && i + 1 < argc) {
            return std::string{argv[i + 1]};
        }
    }
    if (const char* env = std::getenv("SCLI_LOG_LEVEL"); env != nullptr) {  // NOLINT(concurrency-mt-unsafe)
        return std::string{env};
    }
    return "warn";
}


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    // Initialise logging before CLI11 parses anything so that subcommand
    // callbacks (which run inside CLI11_PARSE) already have a live logger.
    scli::cli_init_logging(early_log_level(argc, argv));

    CLI::App app{"scli — safe-crypto-lib command line interface"};
    app.require_subcommand(1);

    std::string log_level = "warn";
    app.add_option("--log-level", log_level,
        "Log verbosity: trace, debug, info, warn, error, critical, off (default: warn)")
        ->envname("SCLI_LOG_LEVEL");

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
