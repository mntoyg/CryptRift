// Everything the user sees is produced here or in a cmd_*.cpp -- never in
// src/core.
#ifndef CRYPTRIFT_CLI_RENDER_HPP
#define CRYPTRIFT_CLI_RENDER_HPP

#include <cryptrift/bytes.hpp>

#include <iosfwd>

namespace cryptrift {
namespace cli {

// Writes the bytes and nothing else: no newline, no translation. This is what
// makes `cryptrift ... -q | base64 -d` safe.
void write_raw(std::ostream& out, const Bytes& data);

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_RENDER_HPP
