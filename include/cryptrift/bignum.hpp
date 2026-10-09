// An arbitrary-precision unsigned integer, written here rather than linked in.
//
// The RSA helpers need numbers of hundreds of bits, and C++ has none. Writing
// modpow and modinv by hand is also half the point of this project. The cost is
// that a silent arithmetic error here would make every answer above it wrong in
// a way no eye would catch, so this module carries the heaviest test burden in
// the repository: a differential test against a 128-bit built-in across
// thousands of random pairs, plus the carry and borrow edges.
//
// This is schoolbook arithmetic and is NOT constant-time. It is for solving
// puzzles, not for protecting anything.
//
// Depends on error.hpp alone, deliberately: faster multiplication could be
// swapped in later without rsa.hpp noticing.
#ifndef CRYPTRIFT_BIGNUM_HPP
#define CRYPTRIFT_BIGNUM_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cryptrift {

class Bignum {
public:
    Bignum() = default;
    explicit Bignum(std::uint64_t value);

    // Accepts an optional 0x prefix, either case, embedded ASCII whitespace,
    // and an odd number of digits -- 0xabc is a value, not a truncated byte
    // pair. Throws Error on an empty or non-hex input.
    static Bignum from_hex(std::string_view text);

    // Lowercase, no leading zeros, "0" for zero.
    std::string to_hex() const;

    // Big-endian bytes, as an RSA modulus or ciphertext arrives. Both
    // directions denote a value, so a leading zero byte does not survive.
    static Bignum from_bytes_be(const std::vector<std::uint8_t>& bytes);
    std::vector<std::uint8_t> to_bytes_be() const;

    bool is_zero() const { return limbs_.empty(); }

    // 0 for zero, otherwise the position of the highest set bit plus one.
    std::size_t bit_length() const;

    // Base 2^32, little-endian, always trimmed so zero is an empty vector.
    // Exposed for the arithmetic below, which is part of this module.
    const std::vector<std::uint32_t>& limbs() const { return limbs_; }
    std::vector<std::uint32_t>& limbs() { return limbs_; }

    // Drops leading zero limbs. Every operation that can shrink a value ends
    // with this, which is what keeps zero's single spelling.
    void trim();

private:
    std::vector<std::uint32_t> limbs_;
};

// -1, 0 or 1.
int compare(const Bignum& left, const Bignum& right);

Bignum add(const Bignum& left, const Bignum& right);

// Throws Error when the result would be negative: this type is unsigned, and
// wrapping silently is how a subtraction bug becomes an RSA answer.
Bignum sub(const Bignum& left, const Bignum& right);

Bignum mul(const Bignum& left, const Bignum& right);

Bignum shl(const Bignum& value, std::size_t bits);

// Shifting past the end yields zero rather than anything undefined.
Bignum shr(const Bignum& value, std::size_t bits);

}  // namespace cryptrift

#endif  // CRYPTRIFT_BIGNUM_HPP
