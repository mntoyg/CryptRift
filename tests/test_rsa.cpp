#include <cryptrift/rsa.hpp>

#include <cryptrift/bignum.hpp>
#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <string>

#include "ct_test.hpp"
#include "rsa_fixtures.hpp"
#include "tests.hpp"

using cryptrift::Bignum;
using cryptrift::from_string;

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
