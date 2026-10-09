// Every test_*.cpp exposes one entry point; main.cpp calls them in order.
#ifndef CRYPTRIFT_TESTS_TESTS_HPP
#define CRYPTRIFT_TESTS_TESTS_HPP

void run_error_tests();
void run_bytes_tests();
void run_codec_tests();
void run_args_tests();
void run_cli_tests();
void run_cli_classical_tests();
void run_cli_xor_tests();
void run_require_long_tests();
void run_flag_tests();
void run_score_tests();
void run_bignum_arith_tests();
void run_classical_tests();
void run_xor_tests();
void run_xor_repeating_tests();

#endif  // CRYPTRIFT_TESTS_TESTS_HPP
