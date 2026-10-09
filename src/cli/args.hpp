// Argument parsing and the exit-code vocabulary.
//
// run() takes its streams as parameters so the whole CLI can be exercised
// in-process; main() is the only place that touches std::cin and std::cout.
#ifndef CRYPTRIFT_CLI_ARGS_HPP
#define CRYPTRIFT_CLI_ARGS_HPP

#include <cryptrift/bytes.hpp>
#include <cryptrift/codec.hpp>

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

int run(const std::vector<std::string>& argv_tail, std::istream& in, std::ostream& out,
        std::ostream& err);

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_ARGS_HPP
