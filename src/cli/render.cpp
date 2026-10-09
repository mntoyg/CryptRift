#include "cli/render.hpp"

#include <cryptrift/codec.hpp>

#include <iomanip>
#include <ostream>
#include <sstream>

namespace cryptrift {
namespace cli {

namespace {

// A long repeating key is more useful shown than hidden, but a table row has
// to stay a row.
std::string preview_key(const Bytes& key) {
    const std::string hex = encode(Format::hex, key);
    if (hex.size() <= 18) return hex;
    return hex.substr(0, 15) + "...";
}

}  // namespace

void write_raw(std::ostream& out, const Bytes& data) {
    if (data.empty()) return;
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::string preview(const Bytes& data, std::size_t width) {
    std::string out;
    const std::size_t shown = data.size() < width ? data.size() : width;
    for (std::size_t index = 0; index < shown; ++index) {
        const std::uint8_t byte = data[index];
        out += (byte >= 0x20 && byte <= 0x7E) ? static_cast<char>(byte) : '.';
    }
    if (data.size() > shown) out += "...";
    return out;
}

void render_candidates(std::ostream& out, const std::vector<Candidate>& hits, std::size_t top) {
    const std::size_t shown = (top == 0 || top > hits.size()) ? hits.size() : top;

    out << "rank  key                   score  plaintext\n";
    for (std::size_t index = 0; index < shown; ++index) {
        const Candidate& hit = hits[index];
        std::ostringstream score;
        score << std::fixed << std::setprecision(2) << hit.score;

        out << std::setw(4) << (index + 1) << "  " << std::left << std::setw(20)
            << preview_key(hit.key) << std::right << std::setw(7) << score.str() << "  "
            << preview(hit.plaintext, 48) << "\n";
    }
}

void render_classical(std::ostream& out, const std::vector<ClassicalCandidate>& hits,
                      std::size_t top) {
    const std::size_t shown = (top == 0 || top > hits.size()) ? hits.size() : top;

    out << "rank  key                   score  plaintext" << "\n";
    for (std::size_t index = 0; index < shown; ++index) {
        const ClassicalCandidate& hit = hits[index];
        std::ostringstream score;
        score << std::fixed << std::setprecision(2) << hit.score;

        std::ostringstream key;
        key << "a=" << hit.a << " b=" << hit.b;

        out << std::setw(4) << (index + 1) << "  " << std::left << std::setw(20) << key.str()
            << std::right << std::setw(7) << score.str() << "  " << preview(hit.plaintext, 48)
            << "\n";
    }
}

}  // namespace cli
}  // namespace cryptrift
