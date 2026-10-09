// Runs the real cryptrift binary and captures what it did.
//
// Most of the suite tests core functions directly, which is the point of
// keeping src/core free of I/O. But exit codes, stream discipline and binary
// output only exist in the assembled program, so those are tested by running
// it.
#ifndef CRYPTRIFT_TESTS_CLI_RUNNER_HPP
#define CRYPTRIFT_TESTS_CLI_RUNNER_HPP

#include <string>

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// CTest passes the binary's path as argv[1] of the test program, which main()
// hands to this. A generated header carrying the path would be written once per
// configuration by a multi-config generator, and CMake refuses that.
void set_cli_binary(std::string path);

// `args` is appended to the binary's path as a shell command line, so it may
// contain quotes. `stdin_data` is fed on standard input.
Run run_cli(const std::string& args, const std::string& stdin_data = "");

#endif  // CRYPTRIFT_TESTS_CLI_RUNNER_HPP
