#include <cryptrift/bytes.hpp>

#include <cryptrift/error.hpp>

#include <fstream>
#include <istream>
#include <iterator>

namespace cryptrift {

Bytes read_stream(std::istream& in) {
    // istreambuf_iterator bypasses formatted extraction, so whitespace and
    // NULs come through untouched.
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

Bytes read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw Error("cannot read " + path);
    return read_stream(file);
}

Bytes from_string(std::string_view text) { return Bytes(text.begin(), text.end()); }

std::string to_string(const Bytes& data) { return std::string(data.begin(), data.end()); }

}  // namespace cryptrift
