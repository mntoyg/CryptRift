#include <iostream>

#include "ct_test.hpp"
#include "tests.hpp"

int main() {
    run_error_tests();

    const int failures = ct::failures();
    if (failures == 0) {
        std::cout << "all checks passed\n";
        return 0;
    }
    std::cerr << failures << " check(s) failed\n";
    return 1;
}
