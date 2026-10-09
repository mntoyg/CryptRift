#include "cli/commands.hpp"

namespace cryptrift {
namespace cli {

const std::vector<Command>& all_commands() {
    static const std::vector<Command> table = {
        {"base", "conv", "base conv [--in-format F] [--out-format F] [INPUT]",
         "Convert between raw, hex, b64, b32, bin and dec.", cmd_base_conv},
        {"xor", "apply", "xor apply (--key TEXT | --key-hex HEX) [INPUT]",
         "XOR with a repeating key. Its own inverse, so this also decrypts.", cmd_xor_apply},
        {"xor", "crack", "xor crack [--keylen-min N --keylen-max N] [-q] [--top N] [INPUT]",
         "Recover the key. Single-byte by default; name a key-length range for a repeating key.",
         cmd_xor_crack},
        {"xor", "crib", "xor crib --crib TEXT [INPUT]",
         "Drag a known plaintext across the ciphertext, showing the key each offset implies.",
         cmd_xor_crib},
    };
    return table;
}

const Command* find_command(std::string_view group, std::string_view command) {
    for (const Command& entry : all_commands()) {
        if (group == entry.group && command == entry.command) return &entry;
    }
    return nullptr;
}

}  // namespace cli
}  // namespace cryptrift
