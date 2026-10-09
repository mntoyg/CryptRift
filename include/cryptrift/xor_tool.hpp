// XOR: apply a key, or find the key.
//
// Repeating-key XOR is its own inverse, so one function covers encryption and
// decryption. The crackers return every surviving candidate ranked, because the
// user, not the tool, decides which plaintext looks right -- but the ranking has
// to put the real answer first, and the tests assert exactly that.
#ifndef CRYPTRIFT_XOR_TOOL_HPP
#define CRYPTRIFT_XOR_TOOL_HPP

#include <cryptrift/bytes.hpp>

#include <cstddef>
#include <vector>

namespace cryptrift {

struct Candidate {
    Bytes key;
    Bytes plaintext;
    double score;
};

// Throws Error when the key is empty: index % 0 is the crash this prevents.
Bytes apply_repeating(const Bytes& data, const Bytes& key);

// All 256 one-byte keys, keeping those whose plaintext is at least
// `min_printable` printable, ranked by english_score. `limit` of 0 means no
// limit. An empty result means no candidate survived -- which is a result, not
// an error.
std::vector<Candidate> crack_single_byte(const Bytes& data, double min_printable,
                                         std::size_t limit);

}  // namespace cryptrift

#endif  // CRYPTRIFT_XOR_TOOL_HPP
