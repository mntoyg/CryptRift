#include "cli/commands.hpp"
#include "cli/render.hpp"

#include <cryptrift/codec.hpp>

#include <istream>
#include <ostream>

namespace cryptrift {
namespace cli {

int cmd_base_conv(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const Format in_format = require_format(args, "--in-format", Format::raw);
    const Format out_format = require_format(args, "--out-format", Format::raw);

    // Decoding happens before a single byte is written, so a malformed blob
    // leaves stdout untouched.
    const Bytes data = load_input(args, in_format, in);
    write_raw(out, from_string(encode(out_format, data)));
    return kOk;
}

}  // namespace cli
}  // namespace cryptrift
