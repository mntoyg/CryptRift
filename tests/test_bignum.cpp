#include <cryptrift/bignum.hpp>

#include <cryptrift/error.hpp>

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bignum;
using cryptrift::add;
using cryptrift::compare;
using cryptrift::divmod;
using cryptrift::mod;
using cryptrift::mul;
using cryptrift::shl;
using cryptrift::shr;
using cryptrift::sub;

namespace {

// The differential tests need a reference implementation, and a 128-bit
// built-in integer is the widest one available without a dependency. It is a
// compiler extension, so it is both guarded and marked as one -- -Wpedantic is
// an error in CI, and Linux CI is what actually enforces this half of the
// suite.
#if defined(__SIZEOF_INT128__)
#define CRYPTRIFT_HAVE_INT128 1
__extension__ typedef unsigned __int128 Reference;

std::string hex_of(Reference value) {
    if (value == 0) return "0";
    static const char* digits = "0123456789abcdef";
    std::string out;
    while (value != 0) {
        out += digits[static_cast<std::size_t>(value & 0xF)];
        value >>= 4;
    }
    return std::string(out.rbegin(), out.rend());
}
#endif

}  // namespace

void run_bignum_arith_tests() {
    // Zero has one spelling. Every operation that can shrink a value trims its
    // leading limbs, so "is this zero" never depends on how it was produced.
    CT_CHECK(Bignum().is_zero());
    CT_CHECK_EQ(Bignum().to_hex(), std::string("0"));
    CT_CHECK_EQ(Bignum(0).bit_length(), static_cast<std::size_t>(0));
    CT_CHECK_EQ(Bignum::from_hex("0007").to_hex(), std::string("7"));
    CT_CHECK_EQ(Bignum::from_hex("0x00").to_hex(), std::string("0"));
    CT_CHECK(Bignum::from_hex("00").is_zero());
    CT_CHECK(Bignum::from_hex("0X0000000000000000000").is_zero());

    CT_CHECK_THROWS(Bignum::from_hex("12g4"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_hex(""), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_hex("0x"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_hex("-1"), cryptrift::Error);

    // An odd number of hex digits is fine for a number, unlike for a byte
    // string: 0xabc is a value, not a truncated pair.
    CT_CHECK_EQ(Bignum::from_hex("abc").to_hex(), std::string("abc"));
    CT_CHECK_EQ(Bignum::from_hex("AbC").to_hex(), std::string("abc"));
    CT_CHECK_EQ(Bignum::from_hex("de ad\nbe ef").to_hex(), std::string("deadbeef"));

    CT_CHECK_EQ(Bignum(0xFFFFFFFFFFFFFFFFull).to_hex(), std::string("ffffffffffffffff"));
    CT_CHECK_EQ(Bignum(1).bit_length(), static_cast<std::size_t>(1));
    CT_CHECK_EQ(Bignum(0xFF).bit_length(), static_cast<std::size_t>(8));
    CT_CHECK_EQ(Bignum(0x100).bit_length(), static_cast<std::size_t>(9));
    CT_CHECK_EQ(Bignum(0xFFFFFFFFFFFFFFFFull).bit_length(), static_cast<std::size_t>(64));

    CT_CHECK(sub(Bignum(5), Bignum(5)).is_zero());  // exact zero stays normalised
    CT_CHECK_THROWS(sub(Bignum(1), Bignum(2)), cryptrift::Error);
    CT_CHECK_THROWS(sub(Bignum(), Bignum(1)), cryptrift::Error);
    CT_CHECK_EQ(compare(Bignum(0), Bignum()), 0);
    CT_CHECK_EQ(compare(Bignum(1), Bignum(2)), -1);
    CT_CHECK_EQ(compare(Bignum(2), Bignum(1)), 1);
    CT_CHECK_EQ(compare(Bignum::from_hex("10000000000000000"), Bignum(0xFFFFFFFFFFFFFFFFull)), 1);
    CT_CHECK(mul(Bignum(123456789), Bignum(0)).is_zero());
    CT_CHECK(mul(Bignum(0), Bignum(0)).is_zero());
    CT_CHECK_EQ(mul(Bignum(1), Bignum(0xDEADBEEF)).to_hex(), std::string("deadbeef"));

#if defined(CRYPTRIFT_HAVE_INT128)
    // Differential test against a 128-bit built-in, fixed seed so a failure is
    // reproducible. This is the real safety net: a silent arithmetic error here
    // would make every RSA answer above it wrong in a way no eye would catch.
    std::mt19937_64 rng(20261009);
    for (int round = 0; round < 5000; ++round) {
        const std::uint64_t left = rng();
        const std::uint64_t right = rng();
        CT_CHECK_EQ(add(Bignum(left), Bignum(right)).to_hex(),
                    hex_of(static_cast<Reference>(left) + right));
        CT_CHECK_EQ(mul(Bignum(left), Bignum(right)).to_hex(),
                    hex_of(static_cast<Reference>(left) * right));
        if (left >= right) {
            CT_CHECK_EQ(sub(Bignum(left), Bignum(right)).to_hex(),
                        hex_of(static_cast<Reference>(left) - right));
        }
    }

    // Carry edges: limb boundaries are where a hand-written add goes wrong.
    for (const std::uint64_t edge : {std::uint64_t{0}, std::uint64_t{1},
                                     std::uint64_t{0xFFFFFFFF}, std::uint64_t{0x100000000},
                                     std::uint64_t{0xFFFFFFFFFFFFFFFF}}) {
        CT_CHECK_EQ(add(Bignum(edge), Bignum(1)).to_hex(),
                    hex_of(static_cast<Reference>(edge) + 1));
        CT_CHECK_EQ(mul(Bignum(edge), Bignum(edge)).to_hex(),
                    hex_of(static_cast<Reference>(edge) * edge));
    }
#endif

    // Multi-limb multiplication, checked against a value worked out by hand.
    CT_CHECK_EQ(mul(Bignum::from_hex("ffffffffffffffff"), Bignum::from_hex("ffffffffffffffff"))
                    .to_hex(),
                std::string("fffffffffffffffe0000000000000001"));

    CT_CHECK_EQ(shl(Bignum(1), 64).to_hex(), std::string("10000000000000000"));
    CT_CHECK_EQ(shl(Bignum(1), 0).to_hex(), std::string("1"));
    CT_CHECK(shl(Bignum(), 100).is_zero());
    CT_CHECK(shr(Bignum(1), 1).is_zero());
    CT_CHECK(shr(Bignum(0xFFFF), 100).is_zero());  // shifted past the end, not undefined
    CT_CHECK_EQ(shr(shl(Bignum(0xABCD), 100), 100).to_hex(), std::string("abcd"));
    CT_CHECK_EQ(shr(Bignum(0xFF), 4).to_hex(), std::string("f"));

    CT_CHECK_EQ(Bignum::from_bytes_be({0x01, 0x00}).to_hex(), std::string("100"));
    CT_CHECK_EQ(Bignum::from_bytes_be({0x00, 0x01}).to_hex(), std::string("1"));  // normalised
    CT_CHECK(Bignum::from_bytes_be({}).is_zero());
    CT_CHECK_EQ(Bignum::from_hex("100").to_bytes_be(), std::vector<std::uint8_t>({0x01, 0x00}));
    CT_CHECK(Bignum().to_bytes_be().empty());
    CT_CHECK_EQ(Bignum::from_hex("deadbeefcafe").to_bytes_be(),
                std::vector<std::uint8_t>({0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}));
    // A byte string round-trips as a value, so a leading zero byte is lost by
    // design: dec and bytes-be both denote a number here.
    CT_CHECK_EQ(Bignum::from_bytes_be({0x00, 0xDE, 0xAD}).to_bytes_be(),
                std::vector<std::uint8_t>({0xDE, 0xAD}));
}

namespace {

// A random value of `limb_count` limbs, built through the public hex reader so
// the generator itself cannot be the thing that is wrong.
Bignum random_bignum(std::mt19937_64& rng, std::size_t limb_count) {
    static const char* digits = "0123456789abcdef";
    std::string hex;
    for (std::size_t limb = 0; limb < limb_count; ++limb) {
        for (int nibble = 0; nibble < 8; ++nibble) hex += digits[rng() & 0xF];
    }
    hex[0] = digits[1 + (rng() % 15)];  // keep the length honest
    return Bignum::from_hex(hex);
}

}  // namespace

void run_bignum_div_tests() {
    // Dividing by zero is a question with no answer, so it is an error rather
    // than a quietly wrong quotient.
    CT_CHECK_THROWS(divmod(Bignum(1), Bignum(0)), cryptrift::Error);
    CT_CHECK_THROWS(divmod(Bignum(0), Bignum(0)), cryptrift::Error);
    CT_CHECK_THROWS(mod(Bignum(1), Bignum(0)), cryptrift::Error);

    cryptrift::DivResult result = divmod(Bignum(0), Bignum(7));
    CT_CHECK(result.quot.is_zero());
    CT_CHECK(result.rem.is_zero());

    result = divmod(Bignum(7), Bignum(9));  // divisor longer than the dividend
    CT_CHECK(result.quot.is_zero());
    CT_CHECK_EQ(result.rem.to_dec(), std::string("7"));

    result = divmod(Bignum(42), Bignum(42));
    CT_CHECK_EQ(result.quot.to_dec(), std::string("1"));
    CT_CHECK(result.rem.is_zero());

    CT_CHECK_EQ(divmod(Bignum(100), Bignum(1)).quot.to_dec(), std::string("100"));
    CT_CHECK_EQ(mod(Bignum(100), Bignum(7)).to_dec(), std::string("2"));

    // Against the built-in operators, on values both sides can hold.
    std::mt19937_64 rng(20261010);
    for (int round = 0; round < 5000; ++round) {
        const std::uint64_t numerator = rng();
        const std::uint64_t divisor = rng() | 1u;
        const cryptrift::DivResult pair = divmod(Bignum(numerator), Bignum(divisor));
        CT_CHECK_EQ(pair.quot.to_dec(), std::to_string(numerator / divisor));
        CT_CHECK_EQ(pair.rem.to_dec(), std::to_string(numerator % divisor));
    }

    // Multi-limb division has no reference to compare against, so it is checked
    // by its own definition instead: a == q*b + r, with r < b. That holds for
    // any correct algorithm, which is what makes it the right assertion.
    for (int round = 0; round < 500; ++round) {
        const std::size_t numerator_limbs = 2 + (rng() % 7);
        const std::size_t divisor_limbs = 1 + (rng() % numerator_limbs);
        const Bignum numerator = random_bignum(rng, numerator_limbs);
        const Bignum divisor = random_bignum(rng, divisor_limbs);

        const cryptrift::DivResult pair = divmod(numerator, divisor);
        CT_CHECK_EQ(add(mul(pair.quot, divisor), pair.rem).to_hex(), numerator.to_hex());
        CT_CHECK(compare(pair.rem, divisor) < 0);
    }

    const Bignum big = Bignum::from_hex("fedcba9876543210fedcba9876543210f1f2f3f4");
    const Bignum small = Bignum::from_hex("123456789abcdef0");
    const cryptrift::DivResult checked = divmod(big, small);
    CT_CHECK_EQ(add(mul(checked.quot, small), checked.rem).to_hex(), big.to_hex());
    CT_CHECK(compare(checked.rem, small) < 0);

    CT_CHECK_EQ(Bignum::from_dec("0").to_hex(), std::string("0"));
    CT_CHECK_EQ(Bignum::from_dec("0009").to_dec(), std::string("9"));
    CT_CHECK_EQ(Bignum().to_dec(), std::string("0"));
    CT_CHECK_EQ(Bignum::from_dec("340282366920938463463374607431768211456").to_hex(),
                std::string("100000000000000000000000000000000"));
    CT_CHECK_EQ(Bignum::from_hex("100000000000000000000000000000000").to_dec(),
                std::string("340282366920938463463374607431768211456"));
    CT_CHECK_EQ(Bignum::from_dec("1 234\n").to_dec(), std::string("1234"));

    CT_CHECK_THROWS(Bignum::from_dec("12a4"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_dec(""), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_dec("-1"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_dec("0x10"), cryptrift::Error);

    // Decimal round-trips at a size that exercises the group-of-nine path.
    for (int round = 0; round < 200; ++round) {
        const Bignum value = random_bignum(rng, 1 + (rng() % 8));
        CT_CHECK_EQ(Bignum::from_dec(value.to_dec()).to_hex(), value.to_hex());
    }
}
