#include "cli/args.hpp"

#include <cryptrift/codec.hpp>
#include <cryptrift/error.hpp>

#include <string>
#include <vector>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Format;
using cryptrift::cli::Args;
using cryptrift::cli::has_flag;
using cryptrift::cli::parse_args;
using cryptrift::cli::require;
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
