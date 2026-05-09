// SPDX-License-Identifier: Apache-2.0

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cmd_aead.hpp"
#include "cmd_digest.hpp"
#include "cmd_ecdh.hpp"
#include "cmd_ecdsa.hpp"
#include "cmd_mac.hpp"
#include "cmd_random.hpp"


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    CLI::App app{"scli — safe-crypto-lib command line interface"};
    app.require_subcommand(1);

    scli::register_aead(app);
    scli::register_digest(app);
    scli::register_ecdh(app);
    scli::register_ecdsa(app);
    scli::register_mac(app);
    scli::register_random(app);

    CLI11_PARSE(app, argc, argv);
    return 0;
}
