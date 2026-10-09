// Proves the harness can fail.
//
// CTest runs this with WILL_FAIL TRUE, so a non-zero exit is the passing
// outcome. If someone breaks ct::fail -- or the counter, or the exit code --
// this test starts "passing" with exit 0, and CTest reports it as a failure.
// The FAILED line it prints to stderr is expected output.
#include "ct_test.hpp"

int main() {
    CT_CHECK(1 == 2);  // deliberately false
    return ct::failures() == 0 ? 0 : 1;
}
