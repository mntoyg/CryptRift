#include <cryptrift/xor_tool.hpp>

#include <cryptrift/error.hpp>
#include <cryptrift/score.hpp>

#include <algorithm>
#include <cstdint>
#include <utility>

namespace cryptrift {
namespace {

int popcount8(std::uint8_t value) {
    int bits = 0;
    while (value != 0) {
        bits += value & 1;
        value = static_cast<std::uint8_t>(value >> 1);
    }
    return bits;
}

double block_distance(const Bytes& data, std::size_t offset_left, std::size_t offset_right,
                      std::size_t length) {
    int bits = 0;
    for (std::size_t index = 0; index < length; ++index) {
        bits += popcount8(static_cast<std::uint8_t>(data[offset_left + index] ^
                                                    data[offset_right + index]));
    }
    return static_cast<double>(bits) / static_cast<double>(length);
}

// "RIFTRIFT" and "RIFT" are the same key written twice. The length heuristic
// genuinely prefers multiples of the real length, so without this the reported
// key would depend on which multiple ranked first.
Bytes smallest_period(const Bytes& key) {
    for (std::size_t period = 1; period < key.size(); ++period) {
        if (key.size() % period != 0) continue;
        bool repeats = true;
        for (std::size_t index = period; index < key.size() && repeats; ++index) {
            if (key[index] != key[index - period]) repeats = false;
        }
        if (repeats) return Bytes(key.begin(), key.begin() + static_cast<std::ptrdiff_t>(period));
    }
    return key;
}

}  // namespace

Bytes apply_repeating(const Bytes& data, const Bytes& key) {
    if (key.empty()) throw Error("xor key must not be empty");

    Bytes out(data.size());
    for (std::size_t index = 0; index < data.size(); ++index) {
        out[index] = static_cast<std::uint8_t>(data[index] ^ key[index % key.size()]);
    }
    return out;
}

std::vector<Candidate> crack_single_byte(const Bytes& data, double min_printable,
                                         std::size_t limit) {
    std::vector<Candidate> hits;
    // Nothing to crack. Returning early also keeps a threshold of 0.0 from
    // admitting 256 empty "answers", since printable_ratio({}) is 0.0.
    if (data.empty()) return hits;

    for (int value = 0; value < 256; ++value) {
        const Bytes key{static_cast<std::uint8_t>(value)};
        Bytes plaintext = apply_repeating(data, key);
        if (printable_ratio(plaintext) < min_printable) continue;
        const double score = english_score(plaintext);
        hits.push_back(Candidate{key, std::move(plaintext), score});
    }

    // stable_sort so equal scores stay in ascending key order: a reproducible
    // ranking is what makes a rank-1 assertion meaningful.
    std::stable_sort(hits.begin(), hits.end(),
                     [](const Candidate& left, const Candidate& right) {
                         return left.score > right.score;
                     });

    if (limit != 0 && hits.size() > limit) hits.resize(limit);
    return hits;
}

std::vector<std::size_t> guess_key_lengths(const Bytes& data, KeyLenRange range,
                                           std::size_t top) {
    std::vector<std::pair<double, std::size_t>> scored;

    for (std::size_t length = (range.min == 0 ? 1 : range.min); length <= range.max; ++length) {
        // A length needs at least two whole blocks to compare.
        if (length * 2 > data.size()) break;
        const std::size_t pairs = data.size() / length - 1;
        if (pairs == 0) continue;

        double total = 0.0;
        for (std::size_t pair = 0; pair < pairs; ++pair) {
            total += block_distance(data, pair * length, (pair + 1) * length, length);
        }
        scored.emplace_back(total / static_cast<double>(pairs), length);
    }

    std::stable_sort(scored.begin(), scored.end(),
                     [](const std::pair<double, std::size_t>& left,
                        const std::pair<double, std::size_t>& right) {
                         return left.first < right.first;
                     });

    std::vector<std::size_t> lengths;
    for (const auto& entry : scored) {
        if (top != 0 && lengths.size() >= top) break;
        lengths.push_back(entry.second);
    }
    return lengths;
}

std::vector<Candidate> crack_repeating(const Bytes& data, KeyLenRange range,
                                       double min_printable, std::size_t limit) {
    std::vector<Candidate> hits;
    if (data.empty()) return hits;

    // A handful of lengths, not one: the best Hamming score is a hint, not an
    // answer, and ranking the resulting plaintexts is the real decision.
    const std::vector<std::size_t> lengths = guess_key_lengths(data, range, 5);

    for (const std::size_t length : lengths) {
        Bytes key;
        key.reserve(length);
        bool solved = true;

        for (std::size_t column = 0; column < length; ++column) {
            Bytes slice;
            for (std::size_t index = column; index < data.size(); index += length) {
                slice.push_back(data[index]);
            }
            // No printable filter per column: a column is one byte out of every
            // `length`, so it is not English and must not be judged as if it
            // were. The filter applies to the reassembled plaintext below.
            const std::vector<Candidate> best = crack_single_byte(slice, 0.0, 1);
            if (best.empty()) {
                solved = false;
                break;
            }
            key.push_back(best.front().key.front());
        }
        if (!solved) continue;

        key = smallest_period(key);
        // Several lengths collapse to the same key; keep the first.
        const bool already_seen =
            std::any_of(hits.begin(), hits.end(),
                        [&key](const Candidate& seen) { return seen.key == key; });
        if (already_seen) continue;

        Bytes plaintext = apply_repeating(data, key);
        if (printable_ratio(plaintext) < min_printable) continue;
        const double score = english_score(plaintext);
        hits.push_back(Candidate{std::move(key), std::move(plaintext), score});
    }

    // Score first, then the shorter key: "RIFTRIFT" decrypts exactly as well as
    // "RIFT" and scores identically, and the shorter one is the answer.
    std::stable_sort(hits.begin(), hits.end(),
                     [](const Candidate& left, const Candidate& right) {
                         if (left.score != right.score) return left.score > right.score;
                         return left.key.size() < right.key.size();
                     });

    if (limit != 0 && hits.size() > limit) hits.resize(limit);
    return hits;
}

std::vector<CribHit> crib_drag(const Bytes& cipher, const Bytes& crib) {
    if (crib.empty()) throw Error("crib must not be empty");

    std::vector<CribHit> hits;
    if (crib.size() > cipher.size()) return hits;

    for (std::size_t offset = 0; offset + crib.size() <= cipher.size(); ++offset) {
        Bytes fragment(crib.size());
        for (std::size_t index = 0; index < crib.size(); ++index) {
            fragment[index] = static_cast<std::uint8_t>(cipher[offset + index] ^ crib[index]);
        }
        hits.push_back(CribHit{offset, std::move(fragment)});
    }
    return hits;
}

}  // namespace cryptrift
