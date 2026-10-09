#include "cli/args.hpp"

#include "cli/commands.hpp"

#include <cryptrift/error.hpp>
#include <cryptrift/version.hpp>

#include <cstddef>
#include <istream>
#include <stdexcept>
#include <ostream>
#include <set>

namespace cryptrift {
namespace cli {
namespace {

// Flags that carry no value. Everything else beginning with a dash takes the
// next token, which is what lets `--shift -5` work: a value is a value even
// when it looks like a flag.
bool is_switch(const std::string& token) {
    static const std::set<std::string> switches = {"-q", "--quiet", "-h", "--help", "--version"};
    return switches.count(token) != 0;
}

bool looks_like_flag(const std::string& token) {
    return token.size() > 1 && token[0] == '-';
}

bool group_exists(const std::string& group) {
    for (const Command& entry : all_commands()) {
        if (group == entry.group) return true;
    }
    return false;
}

// Does `flag` appear in this space-separated list of option names?
bool option_declared(const char* declared, const std::string& flag) {
    const std::string list = std::string(" ") + declared + " ";
    return list.find(" " + flag + " ") != std::string::npos;
}

// An unknown flag is a usage error, not a flag to ignore. The parser treats any
// dash-led token as taking the next argument, so a misspelled option swallows
// the real one after it; `xor crack --quiett --in-format hex <blob>` used to
// decode the literal string "hex" and crack three bytes, printing a confident
// ranked table and exiting 0.
void reject_unknown_options(const Command& command, const Args& args) {
    for (const auto& entry : args.flags) {
        if (!option_declared(command.options, entry.first)) {
            throw Error("unknown option " + entry.first + " for '" + command.group +
                        (command.command[0] == 0 ? "" : std::string(" ") + command.command) +
                        "' (try: cryptrift help " + command.group + ")");
        }
    }
}

void write_group_help(const std::string& group, std::ostream& out) {
    out << "usage: cryptrift <group> <command> [options] [input]\n\n";
    std::string current;
    for (const Command& entry : all_commands()) {
        if (!group.empty() && group != entry.group) continue;
        if (current != entry.group) {
            current = entry.group;
            out << current << "\n";
        }
        out << "  " << entry.usage << "\n      " << entry.summary << "\n"
            << "      options: " << entry.options << "\n";
    }
    out << "\nFormats: raw, hex, b64, b32, bin, dec.\n"
        << "Exit codes: 0 produced a result, 1 found nothing, 2 usage error.\n";
}

}  // namespace

Args parse_args(const std::vector<std::string>& argv_tail) {
    Args args;
    std::vector<std::string> words;

    for (std::size_t index = 0; index < argv_tail.size(); ++index) {
        const std::string& token = argv_tail[index];

        if (is_switch(token)) {
            args.flags[token] = "";
            continue;
        }
        if (looks_like_flag(token)) {
            const std::size_t equals = token.find('=');
            if (equals != std::string::npos) {
                args.flags[token.substr(0, equals)] = token.substr(equals + 1);
                continue;
            }
            if (index + 1 >= argv_tail.size()) throw Error(token + " needs a value");
            args.flags[token] = argv_tail[index + 1];
            ++index;
            continue;
        }
        words.push_back(token);
    }

    if (!words.empty()) args.group = words[0];
    if (words.size() > 1) args.command = words[1];
    if (words.size() > 2) args.positional.assign(words.begin() + 2, words.end());
    return args;
}

bool has_flag(const Args& args, const std::string& flag) { return args.flags.count(flag) != 0; }

std::string require(const Args& args, const std::string& flag) {
    const auto found = args.flags.find(flag);
    if (found == args.flags.end()) throw Error("missing required option " + flag);
    return found->second;
}

Format require_format(const Args& args, const std::string& flag, Format fallback) {
    const auto found = args.flags.find(flag);
    if (found == args.flags.end()) return fallback;
    const std::optional<Format> format = format_from_name(found->second);
    if (!format.has_value()) {
        throw Error("unknown format '" + found->second + "' for " + flag +
                    " (want raw, hex, b64, b32, bin or dec)");
    }
    return *format;
}

Bytes load_input(const Args& args, Format in_format, std::istream& stdin_stream) {
    if (!args.positional.empty() && args.positional.front() != "-") {
        return decode(in_format, args.positional.front());
    }
    if (has_flag(args, "--in")) {
        return decode(in_format, to_string(read_file(args.flags.at("--in"))));
    }
    return decode(in_format, to_string(read_stream(stdin_stream)));
}

std::size_t flag_size(const Args& args, const std::string& flag, std::size_t fallback) {
    const auto found = args.flags.find(flag);
    if (found == args.flags.end()) return fallback;

    const std::string& text = found->second;
    std::size_t consumed = 0;
    unsigned long long value = 0;
    try {
        if (!text.empty() && text[0] == '-') throw std::invalid_argument("negative");
        value = std::stoull(text, &consumed);
    } catch (const std::exception&) {
        throw Error(flag + " wants a non-negative whole number, got '" + text + "'");
    }
    // A partially consumed value is junk: "10x" is not 10.
    if (consumed != text.size()) {
        throw Error(flag + " wants a non-negative whole number, got '" + text + "'");
    }
    return static_cast<std::size_t>(value);
}

std::size_t flag_top(const Args& args) { return flag_size(args, "--top", 10); }

namespace {

// One parser for every whole-number option, so the range check cannot be
// forgotten at one call site. Parsed as long long and then checked, because
// long is 32 bits on some targets and 64 on others, and the accepted range of
// an option should not depend on that.
long long parse_whole(const Args& args, const std::string& flag, long long low,
                      long long high) {
    const std::string text = require(args, flag);
    std::size_t consumed = 0;
    long long value = 0;
    try {
        value = std::stoll(text, &consumed);
    } catch (const std::exception&) {
        throw Error(flag + " wants a whole number, got " + text);
    }
    if (consumed != text.size()) throw Error(flag + " wants a whole number, got " + text);
    if (value < low || value > high) {
        throw Error(flag + " is out of range: " + text);
    }
    return value;
}

}  // namespace

int require_int(const Args& args, const std::string& flag) {
    return static_cast<int>(parse_whole(args, flag, -2147483648LL, 2147483647LL));
}

std::uint32_t require_u32(const Args& args, const std::string& flag) {
    return static_cast<std::uint32_t>(parse_whole(args, flag, 0LL, 4294967295LL));
}

long require_long(const Args& args, const std::string& flag) {
    const std::string text = require(args, flag);
    std::size_t consumed = 0;
    long value = 0;
    try {
        value = std::stol(text, &consumed);
    } catch (const std::exception&) {
        throw Error(flag + " wants a whole number, got " + text);
    }
    if (consumed != text.size()) {
        throw Error(flag + " wants a whole number, got " + text);
    }
    return value;
}

double flag_min_printable(const Args& args) {
    const auto found = args.flags.find("--min-printable");
    if (found == args.flags.end()) return 0.9;

    const std::string& text = found->second;
    std::size_t consumed = 0;
    double value = 0.0;
    try {
        value = std::stod(text, &consumed);
    } catch (const std::exception&) {
        throw Error("--min-printable wants a ratio between 0 and 1, got '" + text + "'");
    }
    if (consumed != text.size() || !(value >= 0.0 && value <= 1.0)) {
        throw Error("--min-printable wants a ratio between 0 and 1, got '" + text + "'");
    }
    return value;
}

bool flag_quiet(const Args& args) { return has_flag(args, "-q") || has_flag(args, "--quiet"); }

int run(const std::vector<std::string>& argv_tail, std::istream& in, std::ostream& out,
        std::ostream& err) {
    try {
        const Args args = parse_args(argv_tail);

        if (has_flag(args, "--version")) {
            out << "cryptrift " << version() << "\n";
            return kOk;
        }
        const bool wants_help =
            args.group == "help" || has_flag(args, "-h") || has_flag(args, "--help");

        if (args.group.empty() && !wants_help) {
            write_group_help("", err);
            throw Error("no command given");
        }
        if (wants_help) {
            // `help xor` and `xor --help` ask the same question.
            const std::string group = (args.group == "help") ? args.command : args.group;
            if (!group.empty() && !group_exists(group)) {
                throw Error("unknown group '" + group + "'");
            }
            write_group_help(group, out);
            return kOk;
        }

        const Command* command = find_command(args.group, args.command);
        Args effective = args;
        if (command == nullptr) {
            // A group that takes no subcommand, such as `analyze FILE`: the
            // second word was input, not a command.
            command = find_command(args.group, "");
            if (command != nullptr && !args.command.empty()) {
                effective.positional.insert(effective.positional.begin(), args.command);
                effective.command.clear();
            }
        }
        if (command == nullptr) {
            throw Error("unknown command '" + args.group +
                        (args.command.empty() ? "" : " " + args.command) +
                        "' (try: cryptrift help)");
        }

        reject_unknown_options(*command, effective);

        const int code = command->handler(effective, in, out, err);

        // A write that failed must not be reported as success. Without this the
        // tool exits 0 having emitted truncated output, which matters most for
        // the pipeline this project is built around: `-q | base64 -d`.
        out.flush();
        if (!out) {
            err << "cryptrift: failed to write output\n";
            return kUsage;
        }
        return code;
    } catch (const std::exception& error) {
        err << "cryptrift: " << error.what() << "\n";
        return kUsage;
    }
}

}  // namespace cli
}  // namespace cryptrift
