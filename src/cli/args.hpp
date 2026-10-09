// Argument parsing and the exit-code vocabulary.
//
// run() takes its streams as parameters so the whole CLI can be exercised
// in-process; main() is the only place that touches std::cin and std::cout.
#ifndef CRYPTRIFT_CLI_ARGS_HPP
#define CRYPTRIFT_CLI_ARGS_HPP

#include <cryptrift/bytes.hpp>
#include <cryptrift/codec.hpp>

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace cryptrift {
namespace cli {

// 0 produced a result, 1 ran correctly and found nothing, 2 was asked wrong.
// The middle one is the whole point: an attack that comes up empty must not
// look like success.
constexpr int kOk = 0;
constexpr int kNoResult = 1;
constexpr int kUsage = 2;

struct Args {
    std::string group;
    std::string command;
    std::vector<std::string> positional;
    std::map<std::string, std::string> flags;  // a valueless flag maps to ""
};

// Throws Error when a flag that takes a value has none.
Args parse_args(const std::vector<std::string>& argv_tail);

bool has_flag(const Args& args, const std::string& flag);

// Throws Error when the flag is absent: a missing --key is a usage mistake,
// not an empty key.
std::string require(const Args& args, const std::string& flag);

// Throws Error when the flag names a format that does not exist.
Format require_format(const Args& args, const std::string& flag, Format fallback);

// Resolves the three input sources in order: a positional value, then --in
// FILE, then the stream. A positional of "-" also means the stream.
Bytes load_input(const Args& args, Format in_format, std::istream& stdin_stream);

// Option values shared by every ranked command. Each throws Error on a value
// that does not parse completely or falls outside its range: "--top 10x" is a
// mistake to report, not a 10 to assume.
std::size_t flag_top(const Args& args);          // --top, default 10, 0 means all
double flag_min_printable(const Args& args);     // --min-printable, default 0.9, in [0, 1]
bool flag_quiet(const Args& args);               // -q / --quiet
std::size_t flag_size(const Args& args, const std::string& flag, std::size_t fallback);

// A required signed whole number, such as --shift or --a. Throws Error when
// absent, empty, or trailed by anything that is not a digit.
long require_long(const Args& args, const std::string& flag);

// Range-checked narrowings. Without these a value is silently truncated to
// the target type: 4294967297 becomes 1, and the tool then reports the
// ciphertext back as if it were the message.
int require_int(const Args& args, const std::string& flag);
std::uint32_t require_u32(const Args& args, const std::string& flag);

int run(const std::vector<std::string>& argv_tail, std::istream& in, std::ostream& out,
        std::ostream& err);

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_ARGS_HPP
