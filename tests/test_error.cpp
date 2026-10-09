#include <cryptrift/error.hpp>
#include <cryptrift/version.hpp>

#include <stdexcept>
#include <string>
#include <type_traits>

#include "ct_test.hpp"
#include "tests.hpp"

void run_error_tests() {
    CT_CHECK_THROWS(throw cryptrift::Error("bad hex"), cryptrift::Error);

    try {
        throw cryptrift::Error("bad hex");
    } catch (const cryptrift::Error& error) {
        CT_CHECK_EQ(std::string(error.what()), std::string("bad hex"));
    }

    // The CLI catches std::runtime_error at the top level, so the relationship
    // is load-bearing, not decoration.
    // Extra parentheses: the template argument's comma would otherwise be read
    // as a second macro argument.
    CT_CHECK((std::is_base_of<std::runtime_error, cryptrift::Error>::value));

    CT_CHECK_EQ(cryptrift::version(), std::string("0.1.0"));
}
