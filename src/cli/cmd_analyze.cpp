#include "cli/commands.hpp"
#include "cli/render.hpp"

#include <cryptrift/analyze.hpp>
#include <cryptrift/codec.hpp>

#include <algorithm>
#include <iomanip>
#include <istream>
#include <ostream>
#include <utility>
#include <vector>

namespace cryptrift {
namespace cli {

int cmd_analyze(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const Format in_format = require_format(args, "--in-format", Format::raw);
    const Bytes data = load_input(args, in_format, in);
    const Report report = analyze(data);

    out << "length            " << data.size() << " bytes\n";
    out << "printable         " << std::fixed << std::setprecision(3) << report.printable_ratio
        << "\n";
    out << "coincidence index " << std::fixed << std::setprecision(5)
        << report.index_of_coincidence << "  (English prose is around 0.072, flat data 0.003)\n";

    out << "looks like        ";
    if (report.likely_encodings.empty()) {
        out << "nothing but raw bytes\n";
    } else {
        for (std::size_t index = 0; index < report.likely_encodings.size(); ++index) {
            if (index != 0) out << ", ";
            out << format_name(report.likely_encodings[index]);
        }
        out << "\n";
    }

    // The ten most common bytes, which is usually where a key or a padding
    // pattern shows itself.
    std::vector<std::pair<std::size_t, int>> ranked;
    for (int byte = 0; byte < 256; ++byte) {
        if (report.counts[static_cast<std::size_t>(byte)] != 0) {
            ranked.emplace_back(report.counts[static_cast<std::size_t>(byte)], byte);
        }
    }
    std::stable_sort(ranked.begin(), ranked.end(),
                     [](const std::pair<std::size_t, int>& left,
                        const std::pair<std::size_t, int>& right) {
                         return left.first > right.first;
                     });

    out << "most common bytes\n";
    const std::size_t shown = ranked.size() < 10 ? ranked.size() : 10;
    for (std::size_t index = 0; index < shown; ++index) {
        const int byte = ranked[index].second;
        const bool printable = byte >= 0x20 && byte <= 0x7E;
        out << "  " << encode(Format::hex, Bytes({static_cast<std::uint8_t>(byte)})) << "  "
            << (printable ? static_cast<char>(byte) : '.') << "  " << ranked[index].first << "\n";
    }
    return kOk;
}

}  // namespace cli
}  // namespace cryptrift
