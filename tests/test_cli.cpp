#include <string>

#include "cli_runner.hpp"
#include "ct_test.hpp"
#include "tests.hpp"

void run_cli_tests() {
    Run result = run_cli("base conv --in-format hex --out-format b64 4d7a");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("TXo="));
    CT_CHECK_EQ(result.err, std::string(""));  // stdout carries results, stderr carries nothing

    // Input from stdin when no positional is given.
    result = run_cli("base conv --in-format hex --out-format raw", "4d7a");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("Mz"));

    // Explicit "-" means stdin too.
    result = run_cli("base conv --in-format hex --out-format raw -", "4d7a");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("Mz"));

    // Bad input: exit 2, message on stderr, and nothing at all on stdout -- a
    // half-written result would corrupt whatever the user piped this into.
    result = run_cli("base conv --in-format hex --out-format b64 zz");
    CT_CHECK_EQ(result.exit_code, 2);
    CT_CHECK(result.err.rfind("cryptrift: ", 0) == 0);
    CT_CHECK_EQ(result.out, std::string(""));

    CT_CHECK_EQ(run_cli("nonsense thing").exit_code, 2);
    CT_CHECK_EQ(run_cli("base nonsense 00").exit_code, 2);
    CT_CHECK_EQ(run_cli("base conv --in-format rot13 00").exit_code, 2);

    CT_CHECK_EQ(run_cli("--version").exit_code, 0);
    CT_CHECK(run_cli("--version").out.find("0.1.0") != std::string::npos);
    CT_CHECK_EQ(run_cli("help").exit_code, 0);
    CT_CHECK(!run_cli("help").out.empty());
    CT_CHECK_EQ(run_cli("help base").exit_code, 0);
    CT_CHECK_EQ(run_cli("").exit_code, 2);  // no arguments is a usage error

    // dec is a big-integer conversion and waits for the bignum module.
    CT_CHECK_EQ(run_cli("base conv --in-format dec --out-format hex 42").exit_code, 2);
}
