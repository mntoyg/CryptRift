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

std::optional<Bignum> small_e_root(const Bignum& ciphertext, std::uint32_t e) {
    if (e == 0) throw Error("the public exponent must not be zero");

    const RootResult root = iroot(ciphertext, e);
    if (!root.exact) return std::nullopt;
    return root.root;
}

Bignum common_modulus(const Bignum& n, const Bignum& e1, const Bignum& c1, const Bignum& e2,
                      const Bignum& c2) {
    if (n.is_zero()) throw Error("the modulus must not be zero");
    if (compare(gcd(e1, e2), Bignum(1)) != 0) {
        throw Error("the common-modulus attack needs exponents with no common factor");
    }

    // Bezout without signed arithmetic. a = e1^-1 mod e2 gives a*e1 - 1 = k*e2
    // for an exact k, so a*e1 + (-k)*e2 = 1, and the negative coefficient is
    // applied by inverting its ciphertext instead of negating an exponent.
    const Bignum a = modinv(e1, e2);
    const DivResult step = divmod(sub(mul(a, e1), Bignum(1)), e2);
    if (!step.rem.is_zero()) {
        throw Error("could not build the exponent relation for these exponents");
    }
    const Bignum k = step.quot;

    const Bignum left = modpow(c1, a, n);
    const Bignum right = modpow(modinv(c2, n), k, n);
    const Bignum recovered = mod(mul(left, right), n);

    // The check that makes this safe to act on: a genuine pair re-encrypts to
    // the ciphertext we were given.
    if (compare(modpow(recovered, e1, n), mod(c1, n)) != 0) {
        throw Error("these ciphertexts are not a common-modulus pair for one message");
    }
    return recovered;
}

}  // namespace cryptrift
