#include <cryptrift/score.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace cryptrift {
namespace {

// Relative frequency of each letter in English text.
constexpr std::array<double, 26> kLetterFrequency = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966,
    0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
    0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

constexpr const char* kCommonBigrams[] = {"th", "he", "in", "er", "an"};

bool is_printable(std::uint8_t byte) {
    return (byte >= 0x20 && byte <= 0x7E) || byte == '\t' || byte == '\n' || byte == '\r';
}

// -1 for anything that is not a letter.
int letter_index(std::uint8_t byte) {
    if (byte >= 'a' && byte <= 'z') return byte - 'a';
    if (byte >= 'A' && byte <= 'Z') return byte - 'A';
    return -1;
}

}  // namespace

double printable_ratio(const Bytes& data) {
    if (data.empty()) return 0.0;
    std::size_t printable = 0;
    for (const std::uint8_t byte : data) {
        if (is_printable(byte)) ++printable;
    }
    return static_cast<double>(printable) / static_cast<double>(data.size());
}

double english_score(const Bytes& data) {
    if (data.empty()) return 0.0;

    std::array<std::size_t, 26> counts{};
    std::size_t letters = 0;
    for (const std::uint8_t byte : data) {
        const int index = letter_index(byte);
        if (index >= 0) {
            ++counts[static_cast<std::size_t>(index)];
            ++letters;
        }
    }

    const double size = static_cast<double>(data.size());

    // Printable, and made of letters. The second term matters: without it a
    // run of digits scores like prose, and a numeric false positive outranks
    // the real plaintext.
    double score = 100.0 * printable_ratio(data);
    score += 50.0 * static_cast<double>(letters) / size;

    // Chi-squared distance from English letter frequency, per letter so the
    // term does not grow with the length of the text. Skipped entirely when
    // there are no letters, which is the division this function must not do.
    if (letters > 0) {
        const double total = static_cast<double>(letters);
        double chi_squared = 0.0;
        for (std::size_t index = 0; index < counts.size(); ++index) {
            const double expected = total * kLetterFrequency[index];
            const double difference = static_cast<double>(counts[index]) - expected;
            chi_squared += (difference * difference) / expected;
        }
        score -= chi_squared / total;
    }

    // A small bonus to separate near-ties; divided by the length rather than
    // by length - 1 so a one-byte input needs no special case.
    std::size_t bigram_hits = 0;
    for (std::size_t index = 0; index + 1 < data.size(); ++index) {
        const int first = letter_index(data[index]);
        const int second = letter_index(data[index + 1]);
        if (first < 0 || second < 0) continue;
        for (const char* bigram : kCommonBigrams) {
            if (first == bigram[0] - 'a' && second == bigram[1] - 'a') {
                ++bigram_hits;
                break;
            }
        }
    }
    score += 10.0 * static_cast<double>(bigram_hits) / size;

    return score;
}

}  // namespace cryptrift
