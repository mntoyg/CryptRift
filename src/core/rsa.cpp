#include <cryptrift/rsa.hpp>

#include <cryptrift/error.hpp>

namespace cryptrift {

KeyParams params(const Bignum& p, const Bignum& q, const Bignum& e) {
    if (compare(p, Bignum(2)) < 0 || compare(q, Bignum(2)) < 0) {
        throw Error("p and q must both be at least 2");
    }
    if (compare(p, q) == 0) {
        throw Error("p and q must be different primes, or phi is not (p-1)(q-1)");
    }
    if (e.is_zero()) throw Error("the public exponent must not be zero");

    KeyParams key;
    key.n = mul(p, q);
    key.phi = mul(sub(p, Bignum(1)), sub(q, Bignum(1)));
    // modinv throws when gcd(e, phi) != 1, which is the honest outcome: that
    // exponent has no private counterpart.
    key.d = modinv(e, key.phi);
    return key;
}

Bignum encrypt(const Bignum& message, const Bignum& e, const Bignum& n) {
    return modpow(message, e, n);
}

Bignum decrypt(const Bignum& ciphertext, const Bignum& d, const Bignum& n) {
    return modpow(ciphertext, d, n);
}

Bignum decrypt_with_primes(const Bignum& ciphertext, const Bignum& p, const Bignum& q,
                           const Bignum& e) {
    const KeyParams key = params(p, q, e);
    return decrypt(ciphertext, key.d, key.n);
}

}  // namespace cryptrift
