// Every test_*.cpp exposes one entry point; main.cpp calls them in order.
#ifndef CRYPTRIFT_TESTS_TESTS_HPP
#define CRYPTRIFT_TESTS_TESTS_HPP

void run_error_tests();
void run_bytes_tests();
void run_codec_tests();
void run_args_tests();
void run_cli_tests();

#endif  // CRYPTRIFT_TESTS_TESTS_HPP
