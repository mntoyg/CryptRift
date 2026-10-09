// Everything the user sees is produced here or in a cmd_*.cpp -- never in
// src/core.
#ifndef CRYPTRIFT_CLI_RENDER_HPP
#define CRYPTRIFT_CLI_RENDER_HPP

#include <cryptrift/bytes.hpp>
#include <cryptrift/xor_tool.hpp>

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

namespace cryptrift {
namespace cli {

// Writes the bytes and nothing else: no newline, no translation. This is what
// makes `cryptrift ... -q | base64 -d` safe.
void write_raw(std::ostream& out, const Bytes& data);

// A ranked table: rank, key as hex, score, and a preview with non-printable
// bytes shown as dots. The key is printed because knowing *why* a candidate
// won is half the answer.
void render_candidates(std::ostream& out, const std::vector<Candidate>& hits, std::size_t top);

// The preview form of a blob, used by every table.
std::string preview(const Bytes& data, std::size_t width);

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_RENDER_HPP
