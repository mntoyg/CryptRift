// The dispatch table.
//
// Adding a command is adding one declaration here and one row in commands.cpp;
// run() needs no edit. Handlers are plain function pointers because they are
// plain functions -- nothing here needs to capture state.
#ifndef CRYPTRIFT_CLI_COMMANDS_HPP
#define CRYPTRIFT_CLI_COMMANDS_HPP

#include "cli/args.hpp"

#include <iosfwd>
#include <string_view>
#include <vector>

namespace cryptrift {
namespace cli {

using Handler = int (*)(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);

struct Command {
    const char* group;
    const char* command;  // "" for a group that takes no subcommand
    const char* usage;
    const char* summary;
    Handler handler;
};

const std::vector<Command>& all_commands();

// nullptr when nothing matches, which run() turns into a usage error.
const Command* find_command(std::string_view group, std::string_view command);

// One declaration per handler, defined in the matching cmd_*.cpp.
int cmd_base_conv(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_xor_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_xor_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_xor_crib(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_caesar_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_caesar_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_affine_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_affine_decrypt(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_affine_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_rsa_params(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_rsa_encrypt(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_rsa_decrypt(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_rsa_smalle(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);
int cmd_rsa_common_modulus(const Args& args, std::istream& in, std::ostream& out,
                           std::ostream& err);
int cmd_rsa_wiener(const Args& args, std::istream& in, std::ostream& out, std::ostream& err);

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_COMMANDS_HPP
