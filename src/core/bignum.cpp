#include <cryptrift/bignum.hpp>

#include <cryptrift/error.hpp>

#include <algorithm>
#include <string>

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

namespace {

constexpr std::uint32_t kLimbMask = 0xFFFFFFFFu;

// Divides by a single limb, which the general path would handle badly: Knuth's
// algorithm needs two divisor limbs to estimate a quotient digit.
DivResult divmod_small(const Bignum& numerator, std::uint32_t divisor) {
    DivResult result;
    std::vector<std::uint32_t>& quotient = result.quot.limbs();
    quotient.assign(numerator.limbs().size(), 0);

    std::uint64_t remainder = 0;
    for (std::size_t index = numerator.limbs().size(); index-- > 0;) {
        const std::uint64_t current = (remainder << 32) | numerator.limbs()[index];
        quotient[index] = static_cast<std::uint32_t>(current / divisor);
        remainder = current % divisor;
    }
    result.quot.trim();
    result.rem = Bignum(remainder);
    return result;
}

}  // namespace

Bignum Bignum::from_dec(std::string_view text) {
    std::string digits;
    digits.reserve(text.size());
    for (const char character : text) {
        if (!is_ascii_space(character)) digits += character;
    }
    if (digits.empty()) throw Error("expected a decimal number, got nothing");

    Bignum result;
    for (const char character : digits) {
        if (character < '0' || character > '9') {
            throw Error(std::string("'") + character + "' is not a decimal digit");
        }
        // result = result * 10 + digit, in one pass over the limbs.
        std::uint64_t carry = static_cast<std::uint64_t>(character - '0');
        for (std::uint32_t& limb : result.limbs_) {
            const std::uint64_t current = static_cast<std::uint64_t>(limb) * 10 + carry;
            limb = static_cast<std::uint32_t>(current & kLimbMask);
            carry = current >> 32;
        }
        while (carry != 0) {
            result.limbs_.push_back(static_cast<std::uint32_t>(carry & kLimbMask));
            carry >>= 32;
        }
    }
    result.trim();
    return result;
}

std::string Bignum::to_dec() const {
    if (limbs_.empty()) return "0";

    // Nine digits at a time: 10^9 is the largest power of ten that fits in a
    // limb, so each division yields a whole group.
    std::vector<std::uint32_t> groups;
    Bignum remaining = *this;
    while (!remaining.is_zero()) {
        const DivResult step = divmod_small(remaining, 1000000000u);
        groups.push_back(step.rem.limbs().empty() ? 0u : step.rem.limbs().front());
        remaining = step.quot;
    }

    std::string out = std::to_string(groups.back());
    for (std::size_t index = groups.size() - 1; index-- > 0;) {
        const std::string group = std::to_string(groups[index]);
        out += std::string(9 - group.size(), '0') + group;
    }
    return out;
}

DivResult divmod(const Bignum& numerator, const Bignum& divisor) {
    if (divisor.is_zero()) throw Error("division by zero");

    if (compare(numerator, divisor) < 0) {
        DivResult result;
        result.rem = numerator;
        return result;
    }
    if (divisor.limbs().size() == 1) return divmod_small(numerator, divisor.limbs().front());

    // Knuth algorithm D. The divisor is first shifted so its top bit is set,
    // which is what makes the two-limb quotient estimate below accurate to
    // within one.
    std::size_t shift = 0;
    std::uint32_t top = divisor.limbs().back();
    while ((top & 0x80000000u) == 0) {
        top <<= 1;
        ++shift;
    }

    const Bignum shifted_divisor = shl(divisor, shift);
    Bignum shifted_numerator = shl(numerator, shift);

    const std::vector<std::uint32_t>& v = shifted_divisor.limbs();
    std::vector<std::uint32_t>& u = shifted_numerator.limbs();

    const std::size_t n = v.size();
    u.push_back(0);  // the extra high limb algorithm D works in
    const std::size_t m = u.size() - n - 1;

    DivResult result;
    std::vector<std::uint32_t>& quotient = result.quot.limbs();
    quotient.assign(m + 1, 0);

    for (std::size_t j = m + 1; j-- > 0;) {
        const std::uint64_t numerator_pair =
            (static_cast<std::uint64_t>(u[j + n]) << 32) | u[j + n - 1];
        std::uint64_t estimate = numerator_pair / v[n - 1];
        std::uint64_t estimate_rem = numerator_pair % v[n - 1];

        // Correct the estimate downwards; it is never off by more than two.
        while (estimate > kLimbMask ||
               estimate * v[n - 2] > ((estimate_rem << 32) | u[j + n - 2])) {
            --estimate;
            estimate_rem += v[n - 1];
            if (estimate_rem > kLimbMask) break;
        }

        // Multiply and subtract.
        std::int64_t borrow = 0;
        std::uint64_t carry = 0;
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint64_t product = estimate * v[i] + carry;
            carry = product >> 32;
            std::int64_t difference = static_cast<std::int64_t>(u[i + j]) -
                                      static_cast<std::int64_t>(product & kLimbMask) - borrow;
            if (difference < 0) {
                difference += static_cast<std::int64_t>(kLimbBase);
                borrow = 1;
            } else {
                borrow = 0;
            }
            u[i + j] = static_cast<std::uint32_t>(difference);
        }
        std::int64_t difference = static_cast<std::int64_t>(u[j + n]) -
                                  static_cast<std::int64_t>(carry) - borrow;
        const bool went_negative = difference < 0;
        if (went_negative) difference += static_cast<std::int64_t>(kLimbBase);
        u[j + n] = static_cast<std::uint32_t>(difference);

        if (went_negative) {
            // The estimate was one too large after all: add the divisor back.
            --estimate;
            std::uint64_t add_carry = 0;
            for (std::size_t i = 0; i < n; ++i) {
                const std::uint64_t sum =
                    static_cast<std::uint64_t>(u[i + j]) + v[i] + add_carry;
                u[i + j] = static_cast<std::uint32_t>(sum & kLimbMask);
                add_carry = sum >> 32;
            }
            u[j + n] = static_cast<std::uint32_t>((u[j + n] + add_carry) & kLimbMask);
        }

        quotient[j] = static_cast<std::uint32_t>(estimate);
    }

    result.quot.trim();

    // What is left in the low n limbs is the remainder, still shifted.
    Bignum remainder;
    remainder.limbs().assign(u.begin(), u.begin() + static_cast<std::ptrdiff_t>(n));
    remainder.trim();
    result.rem = shr(remainder, shift);
    return result;
}

Bignum mod(const Bignum& value, const Bignum& modulus) { return divmod(value, modulus).rem; }

namespace {

// Repeated squaring with a small exponent, for the root check below.
Bignum pow_small(const Bignum& base, std::uint32_t exponent) {
    Bignum result(1);
    Bignum factor = base;
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = mul(result, factor);
        exponent >>= 1;
        if (exponent != 0) factor = mul(factor, factor);
    }
    return result;
}

bool bit_set(const Bignum& value, std::size_t index) {
    const std::size_t limb = index / 32;
    if (limb >= value.limbs().size()) return false;
    return ((value.limbs()[limb] >> (index % 32)) & 1u) != 0;
}

}  // namespace

Bignum gcd(const Bignum& left, const Bignum& right) {
    Bignum a = left;
    Bignum b = right;
    while (!b.is_zero()) {
        Bignum remainder = mod(a, b);
        a = b;
        b = remainder;
    }
    return a;
}

Bignum modpow(const Bignum& base, const Bignum& exponent, const Bignum& modulus) {
    if (modulus.is_zero()) throw Error("modpow needs a modulus greater than zero");

    // 1 mod m, so a modulus of 1 correctly answers 0 even for exponent 0.
    Bignum result = mod(Bignum(1), modulus);
    Bignum square = mod(base, modulus);

    const std::size_t bits = exponent.bit_length();
    for (std::size_t index = 0; index < bits; ++index) {
        if (bit_set(exponent, index)) result = mod(mul(result, square), modulus);
        square = mod(mul(square, square), modulus);
    }
    return result;
}

Bignum modinv(const Bignum& value, const Bignum& modulus) {
    if (modulus.is_zero()) throw Error("modinv needs a modulus greater than zero");

    // Extended Euclid with the coefficients kept as residues modulo m, so an
    // unsigned type is enough: every subtraction is done as an addition of the
    // modulus first.
    Bignum old_remainder = modulus;
    Bignum remainder = mod(value, modulus);
    Bignum old_coefficient;              // 0
    Bignum coefficient = mod(Bignum(1), modulus);

    while (!remainder.is_zero()) {
        const DivResult step = divmod(old_remainder, remainder);

        Bignum next_remainder = step.rem;
        old_remainder = remainder;
        remainder = next_remainder;

        const Bignum scaled = mod(mul(step.quot, coefficient), modulus);
        Bignum next_coefficient = mod(add(old_coefficient, sub(modulus, scaled)), modulus);
        old_coefficient = coefficient;
        coefficient = next_coefficient;
    }

    if (compare(old_remainder, Bignum(1)) != 0) {
        throw Error("no modular inverse exists: the value and the modulus share a factor");
    }
    return old_coefficient;
}

RootResult iroot(const Bignum& value, std::uint32_t k) {
    if (k == 0) throw Error("iroot needs a root of at least 1");
    if (k == 1) return RootResult{value, true};
    if (value.is_zero()) return RootResult{Bignum(), true};
    if (compare(value, Bignum(1)) == 0) return RootResult{Bignum(1), true};

    // Start above the answer: 2^ceil(bits / k) is at least the k-th root.
    const std::size_t bits = value.bit_length();
    Bignum guess = shl(Bignum(1), (bits + k - 1) / k);

    // Newton, stopping when it stops decreasing. The correction loops below are
    // what make the result exactly the floor, whatever the iteration left.
    for (std::size_t round = 0; round < bits + 8; ++round) {
        const Bignum lower_power = pow_small(guess, k - 1);
        if (lower_power.is_zero()) break;
        const Bignum next = divmod(add(mul(Bignum(k - 1), guess), divmod(value, lower_power).quot),
                                   Bignum(k))
                                .quot;
        if (compare(next, guess) >= 0) break;
        guess = next;
    }
    if (guess.is_zero()) guess = Bignum(1);

    while (!guess.is_zero() && compare(pow_small(guess, k), value) > 0) {
        guess = sub(guess, Bignum(1));
    }
    while (compare(pow_small(add(guess, Bignum(1)), k), value) <= 0) {
        guess = add(guess, Bignum(1));
    }

    const bool exact = compare(pow_small(guess, k), value) == 0;
    return RootResult{guess, exact};
}

}  // namespace cryptrift
