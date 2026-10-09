#include <iostream>

#include "cli_runner.hpp"
#include "ct_test.hpp"
#include "tests.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: ct_tests <path-to-cryptrift-binary>\n";
        return 2;
    }
    set_cli_binary(argv[1]);

    run_error_tests();
    run_bytes_tests();
    run_codec_tests();
    run_codec_dec_tests();
    run_args_tests();
    run_cli_tests();
    run_flag_tests();
    run_cli_xor_tests();
    run_cli_classical_tests();
    run_cli_rsa_tests();
    run_cli_analyze_tests();
    run_cli_help_tests();
    run_analyze_tests();
    run_require_long_tests();
    run_score_tests();
    run_rsa_basic_tests();
    run_rsa_attack_tests();
    run_rsa_wiener_tests();
    run_classical_tests();
    run_bignum_arith_tests();
    run_bignum_div_tests();
    run_bignum_mod_tests();
    run_xor_tests();
    run_xor_repeating_tests();

    const int failures = ct::failures();
    if (failures == 0) {
        std::cout << "all checks passed\n";
        return 0;
    }
    std::cerr << failures << " check(s) failed\n";
    return 1;
}
