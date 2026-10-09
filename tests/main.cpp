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
    run_args_tests();
    run_cli_tests();

    const int failures = ct::failures();
    if (failures == 0) {
        std::cout << "all checks passed\n";
        return 0;
    }
    std::cerr << failures << " check(s) failed\n";
    return 1;
}
