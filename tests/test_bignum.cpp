#include <cryptrift/bignum.hpp>

#include <cryptrift/error.hpp>
#include <cryptrift/xor_tool.hpp>

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
using cryptrift::gcd;
using cryptrift::iroot;
using cryptrift::modinv;
using cryptrift::modpow;
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

void run_bignum_mod_tests() {
    CT_CHECK_EQ(gcd(Bignum(48), Bignum(18)).to_dec(), std::string("6"));
    CT_CHECK_EQ(gcd(Bignum(17), Bignum(0)).to_dec(), std::string("17"));
    CT_CHECK_EQ(gcd(Bignum(0), Bignum(17)).to_dec(), std::string("17"));
    CT_CHECK_EQ(gcd(Bignum(0), Bignum(0)).to_dec(), std::string("0"));
    CT_CHECK_EQ(gcd(Bignum(17), Bignum(13)).to_dec(), std::string("1"));

    // Zero and one are where a hand-written modpow goes wrong, and every one of
    // these shows up in real RSA input.
    CT_CHECK_THROWS(modpow(Bignum(2), Bignum(3), Bignum(0)), cryptrift::Error);
    CT_CHECK(modpow(Bignum(2), Bignum(10), Bignum(1)).is_zero());   // everything is 0 mod 1
    CT_CHECK_EQ(modpow(Bignum(2), Bignum(0), Bignum(7)).to_dec(), std::string("1"));
    CT_CHECK(modpow(Bignum(2), Bignum(0), Bignum(1)).is_zero());    // 1 mod 1, not 1
    CT_CHECK(modpow(Bignum(0), Bignum(5), Bignum(7)).is_zero());
    CT_CHECK_EQ(modpow(Bignum(0), Bignum(0), Bignum(7)).to_dec(), std::string("1"));
    CT_CHECK_EQ(modpow(Bignum(4), Bignum(13), Bignum(497)).to_dec(), std::string("445"));
    CT_CHECK_EQ(modpow(Bignum(2), Bignum(10), Bignum(1000)).to_dec(), std::string("24"));

    CT_CHECK_EQ(modinv(Bignum(3), Bignum(11)).to_dec(), std::string("4"));
    CT_CHECK_EQ(modinv(Bignum(17), Bignum(3120)).to_dec(), std::string("2753"));
    CT_CHECK_EQ(modinv(Bignum(1), Bignum(11)).to_dec(), std::string("1"));
    CT_CHECK_THROWS(modinv(Bignum(4), Bignum(8)), cryptrift::Error);   // gcd is 4
    CT_CHECK_THROWS(modinv(Bignum(0), Bignum(11)), cryptrift::Error);
    CT_CHECK_THROWS(modinv(Bignum(5), Bignum(0)), cryptrift::Error);

    cryptrift::RootResult root = iroot(Bignum(1000), 3);
    CT_CHECK_EQ(root.root.to_dec(), std::string("10"));
    CT_CHECK(root.exact);

    root = iroot(Bignum(999), 3);
    CT_CHECK_EQ(root.root.to_dec(), std::string("9"));   // floor, not rounded
    CT_CHECK(!root.exact);

    root = iroot(Bignum(1001), 3);
    CT_CHECK_EQ(root.root.to_dec(), std::string("10"));
    CT_CHECK(!root.exact);

    root = iroot(Bignum::from_dec("1000000000000000000000000000"), 3);
    CT_CHECK_EQ(root.root.to_dec(), std::string("1000000000"));
    CT_CHECK(root.exact);

    CT_CHECK(iroot(Bignum(0), 3).root.is_zero());
    CT_CHECK(iroot(Bignum(0), 3).exact);
    CT_CHECK_EQ(iroot(Bignum(1), 7).root.to_dec(), std::string("1"));
    CT_CHECK_EQ(iroot(Bignum(5), 1).root.to_dec(), std::string("5"));
    CT_CHECK(iroot(Bignum(5), 1).exact);
    CT_CHECK_EQ(iroot(Bignum(2), 3).root.to_dec(), std::string("1"));
    CT_CHECK(!iroot(Bignum(2), 3).exact);
    CT_CHECK_THROWS(iroot(Bignum(5), 0), cryptrift::Error);

    // Exact roots at a size the RSA small-exponent attack actually meets.
    std::mt19937_64 root_rng(20261011);
    for (int round = 0; round < 50; ++round) {
        const Bignum base = random_bignum(root_rng, 1 + (round % 4));
        const Bignum cube = mul(mul(base, base), base);
        const cryptrift::RootResult found = iroot(cube, 3);
        CT_CHECK_EQ(found.root.to_hex(), base.to_hex());
        CT_CHECK(found.exact);
        CT_CHECK(!iroot(add(cube, Bignum(1)), 3).exact);
    }

    // Fermat's little theorem on the secp256k1 field prime: 2^(p-1) = 1 mod p.
    // A 256-bit exponentiation that lands on exactly 1 is a strong signal that
    // modpow and the division under it are right at realistic size.
    const Bignum prime = Bignum::from_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    CT_CHECK_EQ(prime.bit_length(), static_cast<std::size_t>(256));
    CT_CHECK_EQ(modpow(Bignum(2), sub(prime, Bignum(1)), prime).to_dec(), std::string("1"));
    CT_CHECK_EQ(modpow(Bignum(3), sub(prime, Bignum(1)), prime).to_dec(), std::string("1"));

    // And an inverse at the same size, checked by multiplying it back.
    const Bignum value = Bignum::from_hex("deadbeefcafebabe0123456789abcdef");
    const Bignum inverse = modinv(value, prime);
    CT_CHECK_EQ(mod(mul(value, inverse), prime).to_dec(), std::string("1"));
}

void run_bignum_addback_tests() {
    // These three divisions take the add-back correction in Knuth algorithm D:
    // the quotient estimate comes out one too large, the multiply-and-subtract
    // goes negative, and the divisor has to be added back.
    //
    // That branch fires roughly twice in 2^32 quotient digits, so random fuzzing
    // never reaches it -- an instrumented run over 800,005 digits of random
    // multi-limb division hit it zero times. It is also the branch whose failure
    // would corrupt a quotient silently rather than crash, which is exactly the
    // shape this project is organised against. So it is pinned by construction.
    //
    // Every quotient and remainder below was computed independently outside this
    // repository before being written down.
    struct Case {
        const char* numerator;
        const char* divisor;
        const char* quotient;
        const char* remainder;
    };
    static const Case cases[] = {
        {"10000000000000001fffffffd", "8000000000000000ffffffff", "1", "8000000000000000fffffffe"},
        {"18000000000000002fffffffc", "8000000000000000ffffffff", "2", "8000000000000000fffffffe"},
        {"7fffffff80000000fffffffe00000000", "8000000000000000ffffffff", "fffffffe",
         "8000000000000000fffffffe"},
    };

    for (const Case& item : cases) {
        const Bignum numerator = Bignum::from_hex(item.numerator);
        const Bignum divisor = Bignum::from_hex(item.divisor);
        const cryptrift::DivResult result = divmod(numerator, divisor);

        CT_CHECK_EQ(result.quot.to_hex(), std::string(item.quotient));
        CT_CHECK_EQ(result.rem.to_hex(), std::string(item.remainder));
        // And the defining property, independently of the expected values.
        CT_CHECK_EQ(add(mul(result.quot, divisor), result.rem).to_hex(), numerator.to_hex());
        CT_CHECK(compare(result.rem, divisor) < 0);
    }
}

void run_bignum_absurd_root_tests() {
    // A root larger than the value has bits can only be 0 or 1, and must be
    // answered directly. Reaching Newton with k near 2^31 would try to raise a
    // guess to that power, which is a number of billions of bits: the tool
    // would hang while allocating rather than report that the attack does not
    // apply.
    cryptrift::RootResult root = iroot(Bignum(8), 2147483647);
    CT_CHECK_EQ(root.root.to_dec(), std::string("1"));
    CT_CHECK(!root.exact);

    root = iroot(Bignum(1), 2147483647);
    CT_CHECK_EQ(root.root.to_dec(), std::string("1"));
    CT_CHECK(root.exact);

    CT_CHECK(iroot(Bignum(0), 2147483647).root.is_zero());
    CT_CHECK(iroot(Bignum(0), 2147483647).exact);

    // Just inside the boundary it must still be the real root.
    CT_CHECK_EQ(iroot(Bignum(256), 8).root.to_dec(), std::string("2"));
    CT_CHECK(iroot(Bignum(256), 8).exact);
    CT_CHECK_EQ(iroot(Bignum(255), 8).root.to_dec(), std::string("1"));
    CT_CHECK(!iroot(Bignum(255), 8).exact);

    // A key length beyond the data must not read past the end of it.
    CT_CHECK(cryptrift::guess_key_lengths(cryptrift::from_string("abcdefgh"),
                                          cryptrift::KeyLenRange{9223372036854775808ull,
                                                                 9223372036854775809ull},
                                          3)
                 .empty());
    CT_CHECK(cryptrift::crack_repeating(cryptrift::from_string("abcdefgh"),
                                        cryptrift::KeyLenRange{9223372036854775808ull,
                                                               9223372036854775809ull},
                                        0.0, 3)
                 .empty());
}
