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
    // english_score(plaintext), less one point per key byte.
    //
    // The penalty is not cosmetic. A longer key has more free bytes, so solving
    // each column independently can push a longer key's plaintext to a higher
    // raw score than the true key while producing gibberish: measured on a
    // 69-byte ciphertext with a 4-byte key, three over-fitted keys of 15, 16
    // and 15 bytes scored 142.6, 142.0 and 141.8 against the real answer's
    // 141.2. Charging for key length makes the extra bytes pay for themselves.
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

struct KeyLenRange {
    std::size_t min = 2;
    std::size_t max = 40;
};

// Candidate key lengths, most likely first, by mean normalised Hamming
// distance between consecutive blocks: the right length makes consecutive
// blocks look like English xored with English, which is far less noisy than
// two unrelated byte strings. Lengths that do not fit twice into the data are
// skipped, because one block pair measures nothing.
std::vector<std::size_t> guess_key_lengths(const Bytes& data, KeyLenRange range,
                                           std::size_t top);

// Guesses the length, then solves each column of the transposed ciphertext as
// single-byte XOR. Ties are broken towards the shorter key: a key twice the
// real length produces the same plaintext and the same score, so without that
// rule rank 1 would be arbitrary.
std::vector<Candidate> crack_repeating(const Bytes& data, KeyLenRange range,
                                       double min_printable, std::size_t limit);

struct CribHit {
    std::size_t offset;
    Bytes key_fragment;
};

// Every offset where the crib fits, with the key bytes that would put it there.
// Throws Error on an empty crib; returns nothing when the crib is longer than
// the ciphertext.
std::vector<CribHit> crib_drag(const Bytes& cipher, const Bytes& crib);

}  // namespace cryptrift

#endif  // CRYPTRIFT_XOR_TOOL_HPP
