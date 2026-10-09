#include <cryptrift/classical.hpp>

#include <cryptrift/error.hpp>
#include <cryptrift/score.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

namespace cryptrift {
namespace {

constexpr int kAlphabet = 26;

int gcd_int(int left, int right) {
    while (right != 0) {
        const int next = left % right;
        left = right;
        right = next;
    }
    return left < 0 ? -left : left;
}

// Keeps a negative or oversized shift in range: caesar(-1) and caesar(25) are
// the same cipher.
int normalise(int value) {
    const int wrapped = value % kAlphabet;
    return wrapped < 0 ? wrapped + kAlphabet : wrapped;
}

int multiplier_inverse(int a) {
    const int reduced = normalise(a);
    for (int candidate = 1; candidate < kAlphabet; ++candidate) {
        if ((reduced * candidate) % kAlphabet == 1) return candidate;
    }
    throw Error("affine multiplier " + std::to_string(a) + " has no inverse modulo 26 " +
                "(it must be coprime with 26)");
}

void require_invertible(int a) {
    if (gcd_int(normalise(a), kAlphabet) != 1) {
        throw Error("affine multiplier " + std::to_string(a) +
                    " is not coprime with 26, so the cipher cannot be undone");
    }
}

// The shared letter walk. `map` turns a letter's 0-25 index into another.
template <typename Map>
Bytes transform(const Bytes& data, Map map) {
    Bytes out = data;
    for (std::uint8_t& byte : out) {
        if (byte >= 'a' && byte <= 'z') {
            byte = static_cast<std::uint8_t>('a' + map(byte - 'a'));
        } else if (byte >= 'A' && byte <= 'Z') {
            byte = static_cast<std::uint8_t>('A' + map(byte - 'A'));
        }
    }
    return out;
}

std::vector<ClassicalCandidate> rank(std::vector<ClassicalCandidate> hits, std::size_t limit) {
    std::stable_sort(hits.begin(), hits.end(),
                     [](const ClassicalCandidate& left, const ClassicalCandidate& right) {
                         return left.score > right.score;
                     });
    if (limit != 0 && hits.size() > limit) hits.resize(limit);
    return hits;
}

// The twelve multipliers coprime with 26.
std::vector<int> invertible_multipliers() {
    std::vector<int> values;
    for (int a = 1; a < kAlphabet; ++a) {
        if (gcd_int(a, kAlphabet) == 1) values.push_back(a);
    }
    return values;
}

}  // namespace

Bytes affine_encrypt(const Bytes& data, int a, int b) {
    require_invertible(a);
    const int multiplier = normalise(a);
    const int offset = normalise(b);
    return transform(data, [multiplier, offset](int index) {
        return (multiplier * index + offset) % kAlphabet;
    });
}

Bytes affine_decrypt(const Bytes& data, int a, int b) {
    require_invertible(a);
    const int inverse = multiplier_inverse(a);
    const int offset = normalise(b);
    return transform(data, [inverse, offset](int index) {
        return (inverse * (index - offset + kAlphabet)) % kAlphabet;
    });
}

Bytes caesar(const Bytes& data, int shift) { return affine_encrypt(data, 1, shift); }

std::vector<ClassicalCandidate> crack_caesar(const Bytes& data, double min_printable,
                                             std::size_t limit) {
    std::vector<ClassicalCandidate> hits;
    if (data.empty()) return hits;

    for (int shift = 0; shift < kAlphabet; ++shift) {
        Bytes plaintext = affine_decrypt(data, 1, shift);
        if (printable_ratio(plaintext) < min_printable) continue;
        const double score = english_score(plaintext);
        hits.push_back(ClassicalCandidate{1, shift, std::move(plaintext), score});
    }
    return rank(std::move(hits), limit);
}

std::vector<ClassicalCandidate> crack_affine(const Bytes& data, double min_printable,
                                             std::size_t limit) {
    std::vector<ClassicalCandidate> hits;
    if (data.empty()) return hits;

    for (const int multiplier : invertible_multipliers()) {
        for (int offset = 0; offset < kAlphabet; ++offset) {
            Bytes plaintext = affine_decrypt(data, multiplier, offset);
            if (printable_ratio(plaintext) < min_printable) continue;
            const double score = english_score(plaintext);
            hits.push_back(ClassicalCandidate{multiplier, offset, std::move(plaintext), score});
        }
    }
    return rank(std::move(hits), limit);
}

}  // namespace cryptrift
