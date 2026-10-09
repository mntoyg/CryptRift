#include "cli/args.hpp"

#include <cryptrift/codec.hpp>
#include <cryptrift/error.hpp>

#include <cstddef>
#include <string>
#include <vector>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Format;
using cryptrift::cli::Args;
using cryptrift::cli::flag_min_printable;
using cryptrift::cli::flag_quiet;
using cryptrift::cli::flag_top;
using cryptrift::cli::has_flag;
using cryptrift::cli::parse_args;
using cryptrift::cli::require;
using cryptrift::cli::require_long;
using cryptrift::cli::require_format;

void run_args_tests() {
    const Args args = parse_args({"xor", "crack", "--top", "5", "-q", "deadbeef"});
    CT_CHECK_EQ(args.group, std::string("xor"));
    CT_CHECK_EQ(args.command, std::string("crack"));
    CT_CHECK_EQ(args.flags.at("--top"), std::string("5"));
    CT_CHECK_EQ(args.flags.at("-q"), std::string(""));
    CT_CHECK_EQ(args.positional, std::vector<std::string>{"deadbeef"});
    CT_CHECK(has_flag(args, "-q"));
    CT_CHECK(!has_flag(args, "--quiet"));

    // A flag that takes a value and has none is a usage error, not a silently
    // empty value.
    CT_CHECK_THROWS(parse_args({"base", "conv", "--in-format"}), cryptrift::Error);
    CT_CHECK_THROWS(require(args, "--key"), cryptrift::Error);
    CT_CHECK_EQ(require(args, "--top"), std::string("5"));

    // --flag=value is the other spelling people reach for.
    const Args joined = parse_args({"base", "conv", "--in-format=hex", "4d7a"});
    CT_CHECK_EQ(joined.flags.at("--in-format"), std::string("hex"));
    CT_CHECK_EQ(joined.positional, std::vector<std::string>{"4d7a"});

    // A negative number is a value, not a flag.
    const Args negative = parse_args({"caesar", "apply", "--shift", "-5", "abc"});
    CT_CHECK_EQ(negative.flags.at("--shift"), std::string("-5"));
    CT_CHECK_EQ(negative.positional, std::vector<std::string>{"abc"});

    CT_CHECK(require_format(args, "--in-format", Format::raw) == Format::raw);
    const Args formatted = parse_args({"base", "conv", "--in-format", "b64"});
    CT_CHECK(require_format(formatted, "--in-format", Format::raw) == Format::b64);
    const Args bogus = parse_args({"base", "conv", "--in-format", "rot13"});
    CT_CHECK_THROWS(require_format(bogus, "--in-format", Format::raw), cryptrift::Error);

    // A bare "-" means stdin, so it is not a flag either.
    const Args dash = parse_args({"analyze", "-"});
    CT_CHECK_EQ(dash.group, std::string("analyze"));
    CT_CHECK_EQ(dash.command, std::string("-"));
}

void run_flag_tests() {
    const Args bare = parse_args({"xor", "crack", "deadbeef"});
    CT_CHECK_EQ(flag_top(bare), static_cast<std::size_t>(10));   // documented default
    CT_CHECK_EQ(flag_min_printable(bare), 0.9);                  // documented default
    CT_CHECK(!flag_quiet(bare));

    const Args tuned = parse_args({"xor", "crack", "--top", "3", "--min-printable", "0", "-q"});
    CT_CHECK_EQ(flag_top(tuned), static_cast<std::size_t>(3));
    CT_CHECK_EQ(flag_min_printable(tuned), 0.0);
    CT_CHECK(flag_quiet(tuned));
    CT_CHECK(flag_quiet(parse_args({"xor", "crack", "--quiet"})));

    CT_CHECK_THROWS(flag_top(parse_args({"xor", "crack", "--top", "lots"})), cryptrift::Error);
    CT_CHECK_THROWS(flag_top(parse_args({"xor", "crack", "--top", "-1"})), cryptrift::Error);
    CT_CHECK_THROWS(flag_min_printable(parse_args({"xor", "crack", "--min-printable", "2"})),
                    cryptrift::Error);
    CT_CHECK_THROWS(flag_min_printable(parse_args({"xor", "crack", "--min-printable", "-0.5"})),
                    cryptrift::Error);
    CT_CHECK_THROWS(flag_min_printable(parse_args({"xor", "crack", "--min-printable", "most"})),
                    cryptrift::Error);
    // A trailing suffix is junk, not a number: "10x" must not quietly read 10.
    CT_CHECK_THROWS(flag_top(parse_args({"xor", "crack", "--top", "10x"})), cryptrift::Error);
}

void run_require_long_tests() {
    const Args args = parse_args({"caesar", "apply", "--shift", "-3"});
    CT_CHECK_EQ(require_long(args, "--shift"), -3L);
    CT_CHECK_EQ(require_long(parse_args({"affine", "apply", "--a", "11"}), "--a"), 11L);

    CT_CHECK_THROWS(require_long(args, "--a"), cryptrift::Error);  // absent
    CT_CHECK_THROWS(require_long(parse_args({"caesar", "apply", "--shift", "xyz"}), "--shift"),
                    cryptrift::Error);
    CT_CHECK_THROWS(require_long(parse_args({"caesar", "apply", "--shift", "3x"}), "--shift"),
                    cryptrift::Error);
    CT_CHECK_THROWS(require_long(parse_args({"caesar", "apply", "--shift="}), "--shift"),
                    cryptrift::Error);
}
