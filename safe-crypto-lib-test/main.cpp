// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "aead_tests.hpp"
#include "arm_asm_tests.hpp"
#include "ia_asm_tests.hpp"
#include "cross_provider_tests.hpp"
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
#include "ml_dsa_tests.hpp"
#include "ml_kem_tests.hpp"
#include "pqc_cross_provider_tests.hpp"
#include "random_tests.hpp"
#include "rsa_bigint_tests.hpp"
#include "rsa_der_tests.hpp"
#include "rsa_keygen_tests.hpp"
#include "rsa_oaep_tests.hpp"
#include "rsa_pss_tests.hpp"
#include "sigma_i_tests.hpp"
#include "sigma_tests.hpp"
#include "slh_dsa_tests.hpp"


int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
