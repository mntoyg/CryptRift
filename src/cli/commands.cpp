#include "cli/commands.hpp"

namespace cryptrift {
namespace cli {

const std::vector<Command>& all_commands() {
    static const std::vector<Command> table = {
        {"base", "conv", "base conv [--in-format F] [--out-format F] [INPUT]",
         "Convert between raw, hex, b64, b32, bin and dec.", cmd_base_conv},
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
