// SPDX-License-Identifier: Apache-2.0

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
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


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    CLI::App app{"scli — safe-crypto-lib command line interface"};
    app.require_subcommand(1);

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

    CLI11_PARSE(app, argc, argv);
    return 0;
}
