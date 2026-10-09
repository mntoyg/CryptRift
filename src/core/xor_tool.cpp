#include <cryptrift/xor_tool.hpp>

#include <cryptrift/error.hpp>
#include <cryptrift/score.hpp>

#include <algorithm>
#include <cstdint>

namespace cryptrift {

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

}  // namespace cryptrift
