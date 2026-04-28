/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#include <gtest/gtest.h>

#include "aead_tests.hpp"
#include "secure_buffer_tests.hpp"
#include "psa_error_tests.hpp"
#include "asymmetric_tests.hpp"
#include "chacha20_tests.hpp"
#include "digests_tests.hpp"
#include "ecc_tests.hpp"
#include "ecdh_tests.hpp"
#include "init_tests.hpp"
#include "kdf_tests.hpp"
#include "mac_tests.hpp"
#include "random_tests.hpp"
#include "sigma_i_tests.hpp"
#include "sigma_tests.hpp"


int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
