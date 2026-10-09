#include <cstddef>
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

void run_cli_xor_tests() {
    const std::string flag_hex =
        "0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427";
    const std::string flag_text = "The flag is flag{xor_is_not_encryption}";

    // apply: the key is given, the answer is arithmetic.
    Run result = run_cli("xor apply --key-hex 5a --in-format raw --out-format hex abc");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("3b3839"));
    CT_CHECK_EQ(run_cli("xor apply --key Z --in-format raw --out-format hex abc").out,
                std::string("3b3839"));

    // Exactly one of --key and --key-hex. Both, neither, or an empty key is a
    // usage error -- an empty key would reach index % 0.
    CT_CHECK_EQ(run_cli("xor apply --key K --key-hex 4b abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor apply abc").exit_code, 2);
    // --key= rather than --key "": cmd.exe drops an empty quoted argument, so
    // the quoted form would never reach the program at all.
    CT_CHECK_EQ(run_cli("xor apply --key= abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor apply --key-hex zz abc").exit_code, 2);

    // crack: a ranked table by default.
    result = run_cli("xor crack --in-format hex " + flag_hex);
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK(result.out.find(flag_text) != std::string::npos);
    CT_CHECK(result.out.find("5a") != std::string::npos);  // the key is shown, not just the text

    // -q: the best answer as bytes and nothing else, so it pipes.
    result = run_cli("xor crack -q --in-format hex " + flag_hex);
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, flag_text);  // no table, no trailing newline

    // Binary stdout: a 0x0A must leave as one byte. In text mode on Windows it
    // would become 0x0D 0x0A and quietly corrupt a piped plaintext.
    result = run_cli("xor apply --key-hex 00 --in-format hex --out-format raw 0a");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("\n"));
    CT_CHECK_EQ(result.out.size(), static_cast<std::size_t>(1));

    // Found nothing: exit 1, a message on stderr, nothing on stdout.
    result = run_cli("xor crack --min-printable 1.0 --in-format hex 00010203fcfdfe");
    CT_CHECK_EQ(result.exit_code, 1);
    CT_CHECK_EQ(result.out, std::string(""));
    CT_CHECK(result.err.find("no candidate found") != std::string::npos);

    // Repeating-key mode is reached by naming a key-length range.
    const std::string rep_hex =
        "06212374333b32743d2f663720303620332727382b3a2f277220357426212374333b32743d2f66"
        "3a3d3d2f373b27217425212720722d29312169283b266924313e2628337c";
    result = run_cli("xor crack --keylen-min 2 --keylen-max 20 -q --in-format hex " + rep_hex);
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK(result.out.find("cryptanalysis") != std::string::npos);

    CT_CHECK_EQ(run_cli("xor crib --crib flag{ --in-format hex " + flag_hex).exit_code, 0);
    CT_CHECK_EQ(run_cli("xor crib --in-format hex " + flag_hex).exit_code, 2);  // --crib missing

    // Malformed option values are usage errors, not silent defaults.
    CT_CHECK_EQ(run_cli("xor crack --top notanumber abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor crack --min-printable 2.5 abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor crack --min-printable high abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor crack --top 1 --in-format hex " + flag_hex).exit_code, 0);
}

void run_cli_classical_tests() {
    // Multi-word input arrives on stdin: run_cli refuses quotes, because
    // cmd.exe would strip the command's outer pair and mangle the line.
    Run result = run_cli("caesar apply --shift 3", "attack at dawn");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(result.out, std::string("dwwdfn dw gdzq"));

    CT_CHECK_EQ(run_cli("caesar crack -q", "dwwdfn dw gdzq").out, std::string("attack at dawn"));
    CT_CHECK_EQ(run_cli("caesar apply --shift -3", "dwwdfn dw gdzq").out,
                std::string("attack at dawn"));

    // "This is a test message for the cracker" shifted by 3.
    const std::string shifted = "Wklv lv d whvw phvvdjh iru wkh fudfnhu";
    result = run_cli("affine crack", shifted);
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK(result.out.find("a=1") != std::string::npos);  // the key, not just the text
    CT_CHECK(result.out.find("b=3") != std::string::npos);
    CT_CHECK_EQ(run_cli("affine crack -q", shifted).out,
                std::string("This is a test message for the cracker"));

    result = run_cli("affine apply --a 5 --b 8", "the eagle has landed");
    CT_CHECK_EQ(result.exit_code, 0);
    CT_CHECK_EQ(run_cli("affine decrypt --a 5 --b 8", result.out).out,
                std::string("the eagle has landed"));

    // Usage errors, each for its own reason.
    CT_CHECK_EQ(run_cli("affine apply --a 13 --b 0", "abc").exit_code, 2);  // not coprime with 26
    CT_CHECK_EQ(run_cli("affine apply --b 3", "abc").exit_code, 2);         // --a missing
    CT_CHECK_EQ(run_cli("affine apply --a 5", "abc").exit_code, 2);         // --b missing
    CT_CHECK_EQ(run_cli("caesar apply --shift xyz", "abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("caesar apply", "abc").exit_code, 2);               // --shift missing

    // Found nothing: a shift cannot make control bytes printable.
    result = run_cli("caesar crack --in-format hex 000102");
    CT_CHECK_EQ(result.exit_code, 1);
    CT_CHECK_EQ(result.out, std::string(""));
}
