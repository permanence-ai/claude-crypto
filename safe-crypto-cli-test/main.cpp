// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "aead_tests.hpp"
#include "digest_tests.hpp"
#include "ecdh_tests.hpp"
#include "ecdsa_tests.hpp"
#include "help_tests.hpp"
#include "io_tests.hpp"
#include "kdf_tests.hpp"
#include "log_config_tests.hpp"
#include "logging_tests.hpp"
#include "mac_tests.hpp"
#include "ml_dsa_tests.hpp"
#include "ml_kem_tests.hpp"
#include "random_tests.hpp"
#include "rsa_tests.hpp"
#include "slh_dsa_tests.hpp"


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
