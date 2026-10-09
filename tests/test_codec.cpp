#include <cryptrift/codec.hpp>

#include <cryptrift/bytes.hpp>
#include <cryptrift/bignum.hpp>
#include <cryptrift/error.hpp>

#include <cstdint>
#include <string>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::Format;
using cryptrift::decode;
using cryptrift::encode;
using cryptrift::format_from_name;
using cryptrift::format_name;
using cryptrift::from_string;

namespace {

Bytes every_byte_value() {
    Bytes blob(256);
    for (std::size_t i = 0; i < blob.size(); ++i) blob[i] = static_cast<std::uint8_t>(i);
    return blob;
}

}  // namespace

void run_codec_tests() {
    // RFC 4648 vectors.
    CT_CHECK_EQ(encode(Format::b64, from_string("foobar")), std::string("Zm9vYmFy"));
    CT_CHECK_EQ(encode(Format::b64, from_string("fo")), std::string("Zm8="));
    CT_CHECK_EQ(encode(Format::b32, from_string("foobar")), std::string("MZXW6YTBOI======"));
    CT_CHECK_EQ(decode(Format::b64, "Zm9vYmFy"), from_string("foobar"));
    CT_CHECK_EQ(decode(Format::b32, "MZXW6YTBOI======"), from_string("foobar"));

    CT_CHECK_EQ(encode(Format::hex, Bytes({0xDE, 0xAD})), std::string("dead"));
    CT_CHECK_EQ(decode(Format::hex, "DEAD"), Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(encode(Format::bin, Bytes({0x05})), std::string("00000101"));
    CT_CHECK_EQ(decode(Format::bin, "00000101"), Bytes({0x05}));

    // A wrapped CTF blob must decode, not error: hex and base64 are routinely
    // pasted across lines, and a leading 0x is how most tools print a modulus.
    CT_CHECK_EQ(decode(Format::hex, "de ad\n be\tef"), Bytes({0xDE, 0xAD, 0xBE, 0xEF}));
    CT_CHECK_EQ(decode(Format::hex, "0xdead"), Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(decode(Format::hex, "0XDEAD"), Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(decode(Format::b64, "Zm9v\nYmFy"), from_string("foobar"));
    CT_CHECK_EQ(decode(Format::b32, "MZXW6YTB OI======"), from_string("foobar"));

    // Strict where it matters: a blob that fails to decode is information.
    CT_CHECK_THROWS(decode(Format::hex, "abc"), cryptrift::Error);   // odd length
    CT_CHECK_THROWS(decode(Format::hex, "zz"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::b64, "Zm9!"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::b64, "Zm9"), cryptrift::Error);   // bad padding
    CT_CHECK_THROWS(decode(Format::b32, "MZXW6YTBOI"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::bin, "0101"), cryptrift::Error);  // not a whole byte
    CT_CHECK_THROWS(decode(Format::bin, "01021010"), cryptrift::Error);

    // raw is a passthrough, NULs included. The length is given explicitly
    // because a string_view built from a literal would stop at the NUL and the
    // assertion would prove nothing.
    const std::string_view with_nul("any\0thing", 9);
    CT_CHECK_EQ(decode(Format::raw, with_nul), from_string(with_nul));
    CT_CHECK_EQ(decode(Format::raw, with_nul).size(), static_cast<std::size_t>(9));

    // Empty input is empty output, not an error.
    CT_CHECK_EQ(decode(Format::hex, ""), Bytes{});
    CT_CHECK_EQ(encode(Format::hex, Bytes{}), std::string(""));


    CT_CHECK(!format_from_name("rot13").has_value());
    for (const auto format : {Format::raw, Format::hex, Format::b64, Format::b32, Format::bin,
                              Format::dec}) {
        CT_CHECK(format_from_name(format_name(format)).has_value());
        CT_CHECK(format_from_name(format_name(format)).value() == format);
    }

    const Bytes blob = every_byte_value();
    for (const auto format : {Format::raw, Format::hex, Format::b64, Format::b32, Format::bin}) {
        CT_CHECK_EQ(decode(format, encode(format, blob)), blob);
        CT_CHECK_EQ(decode(format, encode(format, Bytes{})), Bytes{});
    }
}

void run_codec_dec_tests() {
    // dec denotes a value, not a byte string: one non-negative integer written
    // in decimal, which is how an RSA modulus or ciphertext arrives.
    CT_CHECK_EQ(decode(Format::dec, "256"), Bytes({0x01, 0x00}));
    CT_CHECK_EQ(encode(Format::dec, Bytes({0x01, 0x00})), std::string("256"));
    CT_CHECK_EQ(decode(Format::dec, "255"), Bytes({0xFF}));
    CT_CHECK_EQ(encode(Format::dec, Bytes({0xFF})), std::string("255"));

    CT_CHECK_EQ(decode(Format::dec, "0"), Bytes{});  // zero carries no bytes
    CT_CHECK_EQ(encode(Format::dec, Bytes{}), std::string("0"));
    CT_CHECK_EQ(decode(Format::dec, " 1 234\n"), decode(Format::dec, "1234"));

    CT_CHECK_THROWS(decode(Format::dec, "-1"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::dec, "12a"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::dec, ""), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::dec, "0x10"), cryptrift::Error);

    CT_CHECK_EQ(encode(Format::dec, decode(Format::hex, "ff00ff00ff00ff00ff")),
                cryptrift::Bignum::from_hex("ff00ff00ff00ff00ff").to_dec());

    // Because it denotes a value, a leading zero byte does not survive the
    // round trip. That is deliberate, and it is why dec stays out of the
    // round-trip loop above, whose blob starts with 0x00.
    CT_CHECK_EQ(decode(Format::dec, encode(Format::dec, Bytes({0x00, 0xDE, 0xAD}))),
                Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(decode(Format::dec, encode(Format::dec, Bytes({0xDE, 0xAD}))),
                Bytes({0xDE, 0xAD}));
}
