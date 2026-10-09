#include <cryptrift/analyze.hpp>

#include <cryptrift/score.hpp>

#include <cstdint>
#include <string>

namespace cryptrift {
namespace {

bool is_ascii_space(std::uint8_t byte) {
    return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r' || byte == '\v' ||
           byte == '\f';
}

// Does every non-whitespace byte belong to this alphabet?
bool all_within(const Bytes& data, const std::string& alphabet, std::size_t& counted) {
    counted = 0;
    for (const std::uint8_t byte : data) {
        if (is_ascii_space(byte)) continue;
        ++counted;
        if (alphabet.find(static_cast<char>(byte)) == std::string::npos) return false;
    }
    return counted != 0;
}

}  // namespace

Report analyze(const Bytes& data) {
    Report report;
    report.printable_ratio = printable_ratio(data);

    for (const std::uint8_t byte : data) ++report.counts[byte];

    // Index of coincidence: the chance two bytes drawn without replacement
    // match. Needs at least two bytes, which is the division this must not do.
    if (data.size() >= 2) {
        double coincidences = 0.0;
        for (const std::size_t count : report.counts) {
            coincidences += static_cast<double>(count) * static_cast<double>(count - 1);
        }
        const double total = static_cast<double>(data.size());
        report.index_of_coincidence = coincidences / (total * (total - 1.0));
    }

    // Most restrictive alphabet first, so a blob that hex and base64 could both
    // explain is offered as hex. Each format also has to agree on length:
    // offering "abc" as hex would be a guess the decoder then rejects.
    struct Guess {
        Format format;
        const char* alphabet;
        std::size_t group;  // required multiple of the non-whitespace length
    };
    static const Guess guesses[] = {
        {Format::bin, "01", 8},
        {Format::dec, "0123456789", 1},
        {Format::hex, "0123456789abcdefABCDEF", 2},
        {Format::b32, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=", 8},
        {Format::b64,
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", 4},
    };

    for (const Guess& guess : guesses) {
        std::size_t counted = 0;
        if (!all_within(data, guess.alphabet, counted)) continue;
        if (counted % guess.group != 0) continue;
        report.likely_encodings.push_back(guess.format);
    }

    return report;
}

}  // namespace cryptrift
