#include <cryptrift/bignum.hpp>

#include <cryptrift/error.hpp>

#include <algorithm>

namespace cryptrift {
namespace {

constexpr std::uint64_t kLimbBase = 1ull << 32;

bool is_ascii_space(char character) {
    return character == ' ' || character == '\t' || character == '\n' || character == '\r' ||
           character == '\v' || character == '\f';
}

int hex_value(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

}  // namespace

Bignum::Bignum(std::uint64_t value) {
    while (value != 0) {
        limbs_.push_back(static_cast<std::uint32_t>(value & 0xFFFFFFFFull));
        value >>= 32;
    }
}

void Bignum::trim() {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
}

std::size_t Bignum::bit_length() const {
    if (limbs_.empty()) return 0;
    std::size_t bits = (limbs_.size() - 1) * 32;
    std::uint32_t top = limbs_.back();
    while (top != 0) {
        ++bits;
        top >>= 1;
    }
    return bits;
}

Bignum Bignum::from_hex(std::string_view text) {
    std::string digits;
    digits.reserve(text.size());
    for (const char character : text) {
        if (!is_ascii_space(character)) digits += character;
    }
    if (digits.size() >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits.erase(0, 2);
    }
    if (digits.empty()) throw Error("expected a hexadecimal number, got nothing");

    Bignum result;
    // Four bits at a time into the low end, shifting what is already there up.
    for (const char character : digits) {
        const int nibble = hex_value(character);
        if (nibble < 0) {
            throw Error(std::string("'") + character + "' is not a hexadecimal digit");
        }
        std::uint64_t carry = static_cast<std::uint64_t>(nibble);
        for (std::uint32_t& limb : result.limbs_) {
            const std::uint64_t shifted = (static_cast<std::uint64_t>(limb) << 4) | carry;
            limb = static_cast<std::uint32_t>(shifted & 0xFFFFFFFFull);
            carry = shifted >> 32;
        }
        if (carry != 0) result.limbs_.push_back(static_cast<std::uint32_t>(carry));
    }
    result.trim();
    return result;
}

std::string Bignum::to_hex() const {
    if (limbs_.empty()) return "0";

    static const char* digits = "0123456789abcdef";
    std::string out;
    // The top limb without leading zeros, then every lower limb in full.
    std::uint32_t top = limbs_.back();
    bool started = false;
    for (int shift = 28; shift >= 0; shift -= 4) {
        const unsigned nibble = (top >> shift) & 0xFu;
        if (nibble != 0 || started) {
            out += digits[nibble];
            started = true;
        }
    }
    for (std::size_t index = limbs_.size() - 1; index-- > 0;) {
        const std::uint32_t limb = limbs_[index];
        for (int shift = 28; shift >= 0; shift -= 4) out += digits[(limb >> shift) & 0xFu];
    }
    return out;
}

Bignum Bignum::from_bytes_be(const std::vector<std::uint8_t>& bytes) {
    Bignum result;
    for (const std::uint8_t byte : bytes) {
        std::uint64_t carry = byte;
        for (std::uint32_t& limb : result.limbs_) {
            const std::uint64_t shifted = (static_cast<std::uint64_t>(limb) << 8) | carry;
            limb = static_cast<std::uint32_t>(shifted & 0xFFFFFFFFull);
            carry = shifted >> 32;
        }
        if (carry != 0) result.limbs_.push_back(static_cast<std::uint32_t>(carry));
    }
    result.trim();
    return result;
}

std::vector<std::uint8_t> Bignum::to_bytes_be() const {
    std::vector<std::uint8_t> bytes;
    for (const std::uint32_t limb : limbs_) {
        bytes.push_back(static_cast<std::uint8_t>(limb & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((limb >> 8) & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((limb >> 16) & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((limb >> 24) & 0xFFu));
    }
    while (!bytes.empty() && bytes.back() == 0) bytes.pop_back();  // leading zeros, once reversed
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

int compare(const Bignum& left, const Bignum& right) {
    const std::vector<std::uint32_t>& a = left.limbs();
    const std::vector<std::uint32_t>& b = right.limbs();
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    for (std::size_t index = a.size(); index-- > 0;) {
        if (a[index] != b[index]) return a[index] < b[index] ? -1 : 1;
    }
    return 0;
}

Bignum add(const Bignum& left, const Bignum& right) {
    const std::vector<std::uint32_t>& a = left.limbs();
    const std::vector<std::uint32_t>& b = right.limbs();

    Bignum result;
    std::vector<std::uint32_t>& out = result.limbs();
    out.reserve(std::max(a.size(), b.size()) + 1);

    std::uint64_t carry = 0;
    for (std::size_t index = 0; index < a.size() || index < b.size() || carry != 0; ++index) {
        std::uint64_t sum = carry;
        if (index < a.size()) sum += a[index];
        if (index < b.size()) sum += b[index];
        out.push_back(static_cast<std::uint32_t>(sum & 0xFFFFFFFFull));
        carry = sum >> 32;
    }
    result.trim();
    return result;
}

Bignum sub(const Bignum& left, const Bignum& right) {
    if (compare(left, right) < 0) {
        throw Error("subtraction would be negative, and this integer is unsigned");
    }

    const std::vector<std::uint32_t>& a = left.limbs();
    const std::vector<std::uint32_t>& b = right.limbs();

    Bignum result;
    std::vector<std::uint32_t>& out = result.limbs();
    out.reserve(a.size());

    std::int64_t borrow = 0;
    for (std::size_t index = 0; index < a.size(); ++index) {
        std::int64_t difference = static_cast<std::int64_t>(a[index]) - borrow;
        if (index < b.size()) difference -= static_cast<std::int64_t>(b[index]);
        if (difference < 0) {
            difference += static_cast<std::int64_t>(kLimbBase);
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push_back(static_cast<std::uint32_t>(difference));
    }
    result.trim();
    return result;
}

Bignum mul(const Bignum& left, const Bignum& right) {
    const std::vector<std::uint32_t>& a = left.limbs();
    const std::vector<std::uint32_t>& b = right.limbs();
    if (a.empty() || b.empty()) return Bignum();

    Bignum result;
    std::vector<std::uint32_t>& out = result.limbs();
    out.assign(a.size() + b.size(), 0);

    // Schoolbook. Each partial product fits in 64 bits because the limbs are
    // 32 bits wide, which is the whole reason for that choice.
    for (std::size_t i = 0; i < a.size(); ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < b.size(); ++j) {
            const std::uint64_t current = static_cast<std::uint64_t>(a[i]) * b[j] + out[i + j] +
                                          carry;
            out[i + j] = static_cast<std::uint32_t>(current & 0xFFFFFFFFull);
            carry = current >> 32;
        }
        std::size_t index = i + b.size();
        while (carry != 0) {
            const std::uint64_t current = out[index] + carry;
            out[index] = static_cast<std::uint32_t>(current & 0xFFFFFFFFull);
            carry = current >> 32;
            ++index;
        }
    }
    result.trim();
    return result;
}

Bignum shl(const Bignum& value, std::size_t bits) {
    if (value.is_zero()) return Bignum();

    const std::size_t whole_limbs = bits / 32;
    const unsigned leftover = static_cast<unsigned>(bits % 32);

    Bignum result;
    std::vector<std::uint32_t>& out = result.limbs();
    out.assign(whole_limbs, 0);

    std::uint32_t carry = 0;
    for (const std::uint32_t limb : value.limbs()) {
        if (leftover == 0) {
            out.push_back(limb);
            continue;
        }
        out.push_back(static_cast<std::uint32_t>((limb << leftover) | carry));
        carry = static_cast<std::uint32_t>(limb >> (32 - leftover));
    }
    if (carry != 0) out.push_back(carry);

    result.trim();
    return result;
}

Bignum shr(const Bignum& value, std::size_t bits) {
    const std::size_t whole_limbs = bits / 32;
    if (whole_limbs >= value.limbs().size()) return Bignum();

    const unsigned leftover = static_cast<unsigned>(bits % 32);

    Bignum result;
    std::vector<std::uint32_t>& out = result.limbs();
    out.assign(value.limbs().begin() + static_cast<std::ptrdiff_t>(whole_limbs),
               value.limbs().end());

    if (leftover != 0) {
        for (std::size_t index = 0; index < out.size(); ++index) {
            out[index] >>= leftover;
            if (index + 1 < out.size()) {
                out[index] |= static_cast<std::uint32_t>(out[index + 1] << (32 - leftover));
            }
        }
    }
    result.trim();
    return result;
}

}  // namespace cryptrift
