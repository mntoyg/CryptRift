#include <cryptrift/analyze.hpp>

#include <cryptrift/bytes.hpp>
#include <cryptrift/codec.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::Format;
using cryptrift::Report;
using cryptrift::analyze;
using cryptrift::from_string;

namespace {

bool mentions(const std::vector<Format>& formats, Format wanted) {
    return std::find(formats.begin(), formats.end(), wanted) != formats.end();
}

}  // namespace

void run_analyze_tests() {
    const Bytes prose = from_string(
        "The art of cryptanalysis is the art of noticing what does not belong. "
        "A repeating key leaves a rhythm in the ciphertext, and once the length "
        "of that rhythm is known the problem falls apart into many small "
        "problems, each of them a single byte wide.");

    const Report english = analyze(prose);
    // Measured at 0.0724 for this sample. The index is computed over the whole
    // byte histogram, so it sits above the familiar letter-only figure of about
    // 0.065; what matters is the gap to flat data below.
    CT_CHECK(english.index_of_coincidence > 0.055);
    CT_CHECK_EQ(english.printable_ratio, 1.0);
    CT_CHECK(english.counts[static_cast<unsigned char>('e')] > 0);
    CT_CHECK(english.counts[0x00] == 0);

    Bytes flat(2600);
    for (std::size_t index = 0; index < flat.size(); ++index) {
        flat[index] = static_cast<std::uint8_t>(index % 256);
    }
    const Report uniform = analyze(flat);
    CT_CHECK(uniform.index_of_coincidence < english.index_of_coincidence);
    CT_CHECK(uniform.index_of_coincidence < 0.01);   // measured 0.0035
    CT_CHECK(uniform.printable_ratio < 0.5);

    // Encoding guesses, most restrictive alphabet first, so hex comes before
    // base64 for a blob both could explain.
    const Report hexish = analyze(from_string("deadbeefcafebabe"));
    CT_CHECK(mentions(hexish.likely_encodings, Format::hex));
    CT_CHECK(mentions(hexish.likely_encodings, Format::b64));
    CT_CHECK(hexish.likely_encodings.front() == Format::hex);

    const Report b64ish = analyze(from_string("Zm9vYmFyZm9vYmFy"));
    CT_CHECK(mentions(b64ish.likely_encodings, Format::b64));
    CT_CHECK(!mentions(b64ish.likely_encodings, Format::hex));   // Z is not a hex digit

    const Report decimal = analyze(from_string("1234567890"));
    CT_CHECK(mentions(decimal.likely_encodings, Format::dec));
    const Report bits = analyze(from_string("01010101"));
    CT_CHECK(bits.likely_encodings.front() == Format::bin);

    // Odd-length hex is not hex, so it must not be offered as a guess.
    CT_CHECK(!mentions(analyze(from_string("abc")).likely_encodings, Format::hex));
    // Nor is anything with a byte outside every alphabet.
    CT_CHECK(analyze(Bytes({0x00, 0xFF})).likely_encodings.empty());

    // The last module that divides by a length: empty and single-byte inputs
    // must be defined rather than NaN.
    const Report empty = analyze(Bytes{});
    CT_CHECK_EQ(empty.index_of_coincidence, 0.0);
    CT_CHECK_EQ(empty.printable_ratio, 0.0);
    CT_CHECK(empty.likely_encodings.empty());
    CT_CHECK(empty.index_of_coincidence == empty.index_of_coincidence);   // not NaN
    CT_CHECK_EQ(analyze(from_string("a")).index_of_coincidence, 0.0);
    CT_CHECK_EQ(analyze(from_string("a")).printable_ratio, 1.0);
}
