#include <cryptrift/codec.hpp>

#include <cryptrift/bignum.hpp>
#include <cryptrift/error.hpp>

#include <cstdint>

namespace cryptrift {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

bool is_ascii_space(char character) {
    return character == ' ' || character == '\t' || character == '\n' || character == '\r' ||
           character == '\v' || character == '\f';
}

// One place for the layout concession, shared by every character-per-group
// format. Without it, a hex blob pasted across three lines would be rejected.
std::string strip_spaces(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char character : text) {
        if (!is_ascii_space(character)) out += character;
    }
    return out;
}

int hex_value(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

int alphabet_value(const char* alphabet, int size, char character) {
    for (int index = 0; index < size; ++index) {
        if (alphabet[index] == character) return index;
    }
    return -1;
}

std::size_t trailing_padding(const std::string& text) {
    std::size_t count = 0;
    while (count < text.size() && text[text.size() - 1 - count] == '=') ++count;
    return count;
}

Bytes decode_hex(std::string_view text) {
    std::string digits = strip_spaces(text);
    if (digits.size() >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits.erase(0, 2);
    }
    if (digits.size() % 2 != 0) throw Error("hex input has an odd number of digits");

    Bytes data;
    data.reserve(digits.size() / 2);
    for (std::size_t index = 0; index < digits.size(); index += 2) {
        const int high = hex_value(digits[index]);
        const int low = hex_value(digits[index + 1]);
        if (high < 0 || low < 0) throw Error("hex input contains a non-hex character");
        data.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return data;
}

std::string encode_hex(const Bytes& data) {
    std::string out;
    out.reserve(data.size() * 2);
    for (const std::uint8_t byte : data) {
        out += kHexDigits[(byte >> 4) & 0x0F];
        out += kHexDigits[byte & 0x0F];
    }
    return out;
}

Bytes decode_bits(std::string_view text) {
    const std::string digits = strip_spaces(text);
    if (digits.size() % 8 != 0) throw Error("binary input is not a whole number of bytes");

    Bytes data;
    data.reserve(digits.size() / 8);
    for (std::size_t index = 0; index < digits.size(); index += 8) {
        unsigned value = 0;
        for (std::size_t bit = 0; bit < 8; ++bit) {
            const char character = digits[index + bit];
            if (character != '0' && character != '1') {
                throw Error("binary input contains a character other than 0 or 1");
            }
            value = (value << 1) | static_cast<unsigned>(character - '0');
        }
        data.push_back(static_cast<std::uint8_t>(value));
    }
    return data;
}

std::string encode_bits(const Bytes& data) {
    std::string out;
    out.reserve(data.size() * 8);
    for (const std::uint8_t byte : data) {
        for (int bit = 7; bit >= 0; --bit) out += ((byte >> bit) & 1) ? '1' : '0';
    }
    return out;
}

// base64 and base32 differ only in alphabet width and group size, so they share
// one bit-packing pass in each direction.
std::string encode_grouped(const Bytes& data, const char* alphabet, int bits_per_character,
                           std::size_t group_characters) {
    std::string out;
    std::uint32_t buffer = 0;
    int pending = 0;
    for (const std::uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        pending += 8;
        while (pending >= bits_per_character) {
            pending -= bits_per_character;
            out += alphabet[(buffer >> pending) & ((1u << bits_per_character) - 1u)];
        }
    }
    if (pending > 0) {
        const int shift = bits_per_character - pending;
        out += alphabet[(buffer << shift) & ((1u << bits_per_character) - 1u)];
    }
    while (out.size() % group_characters != 0) out += '=';
    return out;
}

Bytes decode_grouped(std::string_view text, const char* alphabet, int alphabet_size,
                     int bits_per_character, std::size_t group_characters, const char* label) {
    std::string symbols = strip_spaces(text);

    // Supply missing trailing padding. An unpadded blob is one of the most
    // common CTF pastes, and the '=' characters are layout rather than
    // content -- the same reasoning that accepts a wrapped blob or a leading
    // 0x. A remainder that encodes no whole byte, or that wastes a whole
    // character, is not explicable as missing padding and is still an error.
    const std::size_t remainder = symbols.size() % group_characters;
    if (remainder != 0) {
        const std::size_t bits = remainder * static_cast<std::size_t>(bits_per_character);
        if (bits / 8 == 0 || bits % 8 >= static_cast<std::size_t>(bits_per_character)) {
            throw Error(std::string(label) + " input length is not a multiple of " +
                        std::to_string(group_characters) +
                        " and cannot be explained by missing padding");
        }
        symbols.append(group_characters - remainder, '=');
    }

    const std::size_t padding = trailing_padding(symbols);
    if (padding >= group_characters) {
        throw Error(std::string(label) + " input is all padding");
    }

    Bytes data;
    std::uint32_t buffer = 0;
    int pending = 0;
    for (std::size_t index = 0; index + padding < symbols.size(); ++index) {
        const int value = alphabet_value(alphabet, alphabet_size, symbols[index]);
        if (value < 0) {
            throw Error(std::string(label) + " input contains an invalid character");
        }
        buffer = (buffer << bits_per_character) | static_cast<std::uint32_t>(value);
        pending += bits_per_character;
        if (pending >= 8) {
            pending -= 8;
            data.push_back(static_cast<std::uint8_t>((buffer >> pending) & 0xFFu));
        }
    }
    // The leftover bits are padding. Whether an encoder zeroed them is not
    // checked: the decoded bytes are the same either way, and rejecting a blob
    // over non-canonical padding would cost more than it protects.
    return data;
}

}  // namespace

std::optional<Format> format_from_name(std::string_view name) {
    if (name == "raw") return Format::raw;
    if (name == "hex") return Format::hex;
    if (name == "b64") return Format::b64;
    if (name == "b32") return Format::b32;
    if (name == "bin") return Format::bin;
    if (name == "dec") return Format::dec;
    return std::nullopt;
}

std::string format_name(Format format) {
    switch (format) {
        case Format::raw: return "raw";
        case Format::hex: return "hex";
        case Format::b64: return "b64";
        case Format::b32: return "b32";
        case Format::bin: return "bin";
        case Format::dec: return "dec";
    }
    return "raw";
}

Bytes decode(Format format, std::string_view text) {
    switch (format) {
        case Format::raw: return Bytes(text.begin(), text.end());
        case Format::hex: return decode_hex(text);
        case Format::b64: return decode_grouped(text, kBase64Alphabet, 64, 6, 4, "base64");
        case Format::b32: return decode_grouped(text, kBase32Alphabet, 32, 5, 8, "base32");
        case Format::bin: return decode_bits(text);
        // dec is a big-integer conversion, so it delegates to bignum rather
        // than carrying a second implementation of the same arithmetic.
        case Format::dec: return Bignum::from_dec(text).to_bytes_be();
    }
    throw Error("unknown format");
}

std::string encode(Format format, const Bytes& data) {
    switch (format) {
        case Format::raw: return to_string(data);
        case Format::hex: return encode_hex(data);
        case Format::b64: return encode_grouped(data, kBase64Alphabet, 6, 4);
        case Format::b32: return encode_grouped(data, kBase32Alphabet, 5, 8);
        case Format::bin: return encode_bits(data);
        case Format::dec: return Bignum::from_bytes_be(data).to_dec();
    }
    throw Error("unknown format");
}

}  // namespace cryptrift
