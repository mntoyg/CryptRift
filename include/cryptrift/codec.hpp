// How a blob is written down, and how to move between those writings.
//
// raw is bytes as-is. hex, b64, b32 and bin are character-per-group encodings.
// dec is the odd one out: it reads the whole input as a single non-negative
// big-endian integer in decimal, which is how RSA moduli and ciphertexts arrive
// in challenges, so a value's leading zeroes do not survive a round trip
// through it.
#ifndef CRYPTRIFT_CODEC_HPP
#define CRYPTRIFT_CODEC_HPP

#include <cryptrift/bytes.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace cryptrift {

enum class Format { raw, hex, b64, b32, bin, dec };

// "hex" -> Format::hex; nullopt for anything else, so the CLI can report an
// unknown format as a usage error rather than guessing.
std::optional<Format> format_from_name(std::string_view name);
std::string format_name(Format format);

// Throws Error on input the format cannot represent. Deliberately strict: a
// CTF blob that fails to decode is information, so it is not quietly repaired.
// The one concession is layout -- ASCII whitespace is skipped, and hex may
// carry a leading 0x, because wrapped pastes are the normal case.
Bytes decode(Format format, std::string_view text);
std::string encode(Format format, const Bytes& data);

}  // namespace cryptrift

#endif  // CRYPTRIFT_CODEC_HPP
