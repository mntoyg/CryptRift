// Every test_*.cpp exposes one entry point; main.cpp calls them in order.
#ifndef CRYPTRIFT_TESTS_TESTS_HPP
#define CRYPTRIFT_TESTS_TESTS_HPP

void run_error_tests();
void run_bytes_tests();
void run_codec_dec_tests();
void run_codec_unpadded_tests();
void run_codec_tests();
void run_analyze_tests();
void run_args_tests();
void run_cli_analyze_tests();
void run_cli_tests();
void run_cli_classical_tests();
void run_cli_absurd_value_tests();
void run_cli_help_tests();
void run_cli_strict_option_tests();
void run_require_int_tests();
void run_write_failure_tests();
void run_cli_rsa_tests();
void run_cli_xor_tests();
void run_require_long_tests();
void run_flag_tests();
void run_rsa_attack_tests();
void run_rsa_wiener_tests();
void run_rsa_basic_tests();
void run_score_tests();
void run_bignum_absurd_root_tests();
void run_bignum_addback_tests();
void run_bignum_arith_tests();
void run_bignum_div_tests();
void run_bignum_mod_tests();
void run_classical_tests();
void run_xor_tests();
void run_xor_repeating_tests();

#endif  // CRYPTRIFT_TESTS_TESTS_HPP
