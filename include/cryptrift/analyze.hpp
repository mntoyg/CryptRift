// Reconnaissance on a blob you know nothing about.
//
// Before attacking something you want to know what it is: how much of it is
// printable, whether its byte distribution looks like language or like noise,
// and whether it is really a hex or base64 wrapper around something else. None
// of this decides anything; it points.
#ifndef CRYPTRIFT_ANALYZE_HPP
#define CRYPTRIFT_ANALYZE_HPP

#include <cryptrift/bytes.hpp>
#include <cryptrift/codec.hpp>

#include <array>
#include <cstddef>
#include <vector>

namespace cryptrift {

struct Report {
    std::array<std::size_t, 256> counts{};

    // Index of coincidence over the whole byte histogram. English prose
    // measures around 0.072 this way and flat data around 0.003, so the gap,
    // not the absolute number, is the signal. It is 0.0 for inputs shorter than
    // two bytes rather than NaN.
    double index_of_coincidence = 0.0;

    double printable_ratio = 0.0;

    // Formats whose alphabet and length could explain every byte, most
    // restrictive alphabet first, so hex precedes base64 for a blob both would
    // accept. Empty when nothing fits. raw is never listed: it always fits.
    std::vector<Format> likely_encodings;
};

Report analyze(const Bytes& data);

}  // namespace cryptrift

#endif  // CRYPTRIFT_ANALYZE_HPP
