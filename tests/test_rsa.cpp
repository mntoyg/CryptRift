#include <cryptrift/rsa.hpp>

#include <cryptrift/bignum.hpp>
#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <string>

#include "ct_test.hpp"
#include "rsa_fixtures.hpp"
#include "tests.hpp"

using cryptrift::Bignum;
using cryptrift::add;
using cryptrift::from_string;
using cryptrift::mul;
using cryptrift::sub;

void run_rsa_basic_tests() {
    // The textbook key, so the arithmetic can be checked against numbers anyone
    // can reproduce by hand.
    const cryptrift::KeyParams key = cryptrift::params(Bignum(61), Bignum(53), Bignum(17));
    CT_CHECK_EQ(key.n.to_dec(), std::string("3233"));
    CT_CHECK_EQ(key.phi.to_dec(), std::string("3120"));
    CT_CHECK_EQ(key.d.to_dec(), std::string("2753"));

    CT_CHECK_EQ(cryptrift::encrypt(Bignum(65), Bignum(17), key.n).to_dec(), std::string("2790"));
    CT_CHECK_EQ(cryptrift::decrypt(Bignum(2790), key.d, key.n).to_dec(), std::string("65"));

    // An exponent sharing a factor with phi has no inverse, so there is no
    // private key to report. That is a usage error, not a key of zero.
    CT_CHECK_THROWS(cryptrift::params(Bignum(61), Bignum(53), Bignum(2)), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::params(Bignum(61), Bignum(53), Bignum(0)), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::params(Bignum(0), Bignum(53), Bignum(17)), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::params(Bignum(1), Bignum(53), Bignum(17)), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::params(Bignum(53), Bignum(53), Bignum(17)), cryptrift::Error);

    // Realistic size, which is the point of writing a bignum at all: a 512-bit
    // modulus from two 256-bit primes, carrying a flag as the message.
    const Bignum p = Bignum::from_dec(fixtures::kP);
    const Bignum q = Bignum::from_dec(fixtures::kQ);
    const Bignum e(65537);

    const cryptrift::KeyParams big = cryptrift::params(p, q, e);
    CT_CHECK_EQ(big.n.to_dec(), std::string(fixtures::kN));
    CT_CHECK_EQ(big.phi.to_dec(), std::string(fixtures::kPhi));
    CT_CHECK_EQ(big.d.to_dec(), std::string(fixtures::kD));
    CT_CHECK_EQ(big.n.bit_length(), static_cast<std::size_t>(512));

    const Bignum message = Bignum::from_bytes_be(from_string("flag{rsa_at_real_size}"));
    const Bignum ciphertext = cryptrift::encrypt(message, e, big.n);
    CT_CHECK_EQ(cryptrift::decrypt(ciphertext, big.d, big.n).to_hex(), message.to_hex());

    // And the plaintext comes back as the flag, not just as a number.
    CT_CHECK_EQ(cryptrift::to_string(cryptrift::decrypt(ciphertext, big.d, big.n).to_bytes_be()),
                std::string("flag{rsa_at_real_size}"));

    // Decrypting from p, q and e takes the same route as decrypting from d.
    CT_CHECK_EQ(cryptrift::decrypt_with_primes(ciphertext, p, q, e).to_hex(), message.to_hex());
}

void run_rsa_attack_tests() {
    // m^e < n, so the ciphertext is a perfect cube and the message is simply
    // its cube root. No key needed.
    const Bignum small_message = Bignum::from_dec(fixtures::kSmallM);
    const Bignum cube = Bignum::from_dec(fixtures::kSmallC);
    CT_CHECK_EQ(mul(mul(small_message, small_message), small_message).to_hex(), cube.to_hex());

    const auto root = cryptrift::small_e_root(cube, 3);
    CT_CHECK(root.has_value());
    CT_CHECK_EQ(root->to_hex(), small_message.to_hex());
    CT_CHECK_EQ(cryptrift::to_string(root->to_bytes_be()), std::string("flag{small_e}"));

    // Not a perfect power: a no-result, not an error and above all not the
    // floor of the root dressed up as an answer.
    CT_CHECK(!cryptrift::small_e_root(add(cube, Bignum(1)), 3).has_value());
    CT_CHECK(!cryptrift::small_e_root(sub(cube, Bignum(1)), 3).has_value());
    CT_CHECK(!cryptrift::small_e_root(Bignum(2), 3).has_value());
    CT_CHECK(cryptrift::small_e_root(Bignum(0), 3).has_value());   // 0 is 0 cubed
    CT_CHECK(cryptrift::small_e_root(Bignum(8), 3).has_value());
    CT_CHECK_EQ(cryptrift::small_e_root(Bignum(8), 3)->to_dec(), std::string("2"));
    CT_CHECK_THROWS(cryptrift::small_e_root(cube, 0), cryptrift::Error);

    // One modulus, two exponents, one message: the message falls out without
    // either private key.
    const Bignum n = Bignum::from_dec(fixtures::kN);
    const Bignum e1(17);
    const Bignum e2(65537);
    const Bignum c1 = Bignum::from_dec(fixtures::kC1);
    const Bignum c2 = Bignum::from_dec(fixtures::kC2);
    const Bignum expected = Bignum::from_dec(fixtures::kMessage);

    const Bignum recovered = cryptrift::common_modulus(n, e1, c1, e2, c2);
    CT_CHECK_EQ(recovered.to_hex(), expected.to_hex());
    CT_CHECK_EQ(cryptrift::to_string(recovered.to_bytes_be()), std::string("flag{common_modulus}"));

    // Exponents that share a factor cannot support the attack at all. That is
    // the caller asking for the wrong thing, so it is an error rather than an
    // empty answer.
    CT_CHECK_THROWS(cryptrift::common_modulus(n, Bignum(4), c1, Bignum(6), c2), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::common_modulus(n, e1, c1, e1, c2), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::common_modulus(Bignum(0), e1, c1, e2, c2), cryptrift::Error);

    // Ciphertexts that are not a genuine pair for one message: arriving at a
    // value here would mean the attack had "succeeded" on nonsense, so it is
    // checked by re-encrypting before anything is returned.
    CT_CHECK_THROWS(cryptrift::common_modulus(n, e1, add(c1, Bignum(1)), e2, c2),
                    cryptrift::Error);
}

void run_rsa_wiener_tests() {
    // A key whose private exponent is small enough for Wiener to reach: 127
    // bits against a 512-bit modulus, inside the one-third-of-the-fourth-root
    // bound.
    const Bignum n = Bignum::from_dec(fixtures::kWienerN);
    const Bignum e = Bignum::from_dec(fixtures::kWienerE);
    const Bignum d = Bignum::from_dec(fixtures::kWienerD);

    const auto found = cryptrift::wiener(n, e);
    CT_CHECK(found.has_value());
    if (found.has_value()) {
        CT_CHECK_EQ(found->to_dec(), d.to_dec());

        // And the recovered exponent actually decrypts, which is the property
        // that matters rather than matching a number in a fixture.
        const Bignum probe(42);
        CT_CHECK_EQ(cryptrift::decrypt(cryptrift::encrypt(probe, e, n), *found, n).to_dec(),
                    std::string("42"));
    }

    // A safe key: Wiener must give up. This is the important assertion in the
    // file -- the continued fraction offers many candidates and almost all are
    // wrong, so an unverified "success" here is exactly the failure this
    // project is organised against.
    const Bignum safe_n = Bignum::from_dec(fixtures::kN);
    CT_CHECK(!cryptrift::wiener(safe_n, Bignum(65537)).has_value());

    // The textbook key is small but its d is not: n^0.25 is under 8, d is 2753.
    CT_CHECK(!cryptrift::wiener(Bignum(3233), Bignum(17)).has_value());

    CT_CHECK_THROWS(cryptrift::wiener(Bignum(0), Bignum(17)), cryptrift::Error);
    CT_CHECK_THROWS(cryptrift::wiener(Bignum(3233), Bignum(0)), cryptrift::Error);
}
