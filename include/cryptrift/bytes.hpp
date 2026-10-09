// The data type everything else speaks, and the two ways to get some.
//
// Bytes carries no interpretation: it is not text, not hex, not base64. What a
// blob means is codec's business, and reading stdin is the CLI's business --
// putting a stream into binary mode is I/O, which src/core does not do.
#ifndef CRYPTRIFT_BYTES_HPP
#define CRYPTRIFT_BYTES_HPP

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace cryptrift {

using Bytes = std::vector<std::uint8_t>;

// Reads to end of stream. Binary-safe: embedded NULs are data like any other.
Bytes read_stream(std::istream& in);

// Throws Error when the file cannot be opened.
Bytes read_file(const std::string& path);

Bytes from_string(std::string_view text);
std::string to_string(const Bytes& data);

}  // namespace cryptrift

#endif  // CRYPTRIFT_BYTES_HPP
