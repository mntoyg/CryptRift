// Caesar and affine: the ciphers whose whole keyspace fits in a loop.
//
// Both act on A-Z and a-z and leave every other byte alone, so punctuation and
// UTF-8 sequences survive. Caesar is the affine cipher with a multiplier of 1,
// and is implemented that way rather than duplicated.
#ifndef CRYPTRIFT_CLASSICAL_HPP
#define CRYPTRIFT_CLASSICAL_HPP

#include <cryptrift/bytes.hpp>

#include <cstddef>
#include <vector>

namespace cryptrift {

// E(x) = (a*x + b) mod 26, case preserved.
//
// `a` must be coprime with 26 or the map collapses letters together and cannot
// be undone; that throws Error rather than quietly producing a cipher nobody
// can decrypt. `b` may be any integer and is normalised into range.
Bytes affine_encrypt(const Bytes& data, int a, int b);
Bytes affine_decrypt(const Bytes& data, int a, int b);

// Shift by `shift`, which may be negative or larger than 26.
Bytes caesar(const Bytes& data, int shift);

// The key as it was applied, so the numbers read the way the challenge states
// them: `a` and `b` are the encryption key, and plaintext is what decrypting
// with that key produced.
struct ClassicalCandidate {
    int a;
    int b;
    Bytes plaintext;
    double score;
};

// Every key in the space, filtered by printability and ranked by english_score.
// `limit` of 0 means no limit. Empty means nothing survived the filter.
std::vector<ClassicalCandidate> crack_caesar(const Bytes& data, double min_printable,
                                             std::size_t limit);
std::vector<ClassicalCandidate> crack_affine(const Bytes& data, double min_printable,
                                             std::size_t limit);

}  // namespace cryptrift

#endif  // CRYPTRIFT_CLASSICAL_HPP
