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

namespace {

// A small value coprime with n, to test a candidate exponent against.
Bignum verification_probe(const Bignum& n) {
    for (const std::uint32_t candidate : {42u, 2u, 3u, 5u, 7u, 11u, 13u}) {
        const Bignum probe(candidate);
        if (compare(probe, n) >= 0) continue;
        if (compare(gcd(probe, n), Bignum(1)) == 0) return probe;
    }
    return Bignum();
}

// Does this exponent actually decrypt? The only question that settles it.
bool exponent_round_trips(const Bignum& n, const Bignum& e, const Bignum& d) {
    const Bignum probe = verification_probe(n);
    if (probe.is_zero()) return false;
    return compare(modpow(modpow(probe, e, n), d, n), probe) == 0;
}

// Given a candidate phi, do the implied p and q multiply back to n?
bool phi_factors_n(const Bignum& n, const Bignum& phi) {
    // p and q are the roots of x^2 - (n - phi + 1)x + n.
    const Bignum sum_candidate = add(sub(n, phi), Bignum(1));  // requires phi <= n
    const Bignum square = mul(sum_candidate, sum_candidate);
    const Bignum four_n = mul(Bignum(4), n);
    if (compare(square, four_n) < 0) return false;

    const RootResult root = iroot(sub(square, four_n), 2);
    if (!root.exact) return false;

    const Bignum twice_p = add(sum_candidate, root.root);
    const DivResult p_half = divmod(twice_p, Bignum(2));
    if (!p_half.rem.is_zero()) return false;

    const Bignum p = p_half.quot;
    if (p.is_zero() || compare(p, sum_candidate) > 0) return false;
    const Bignum q = sub(sum_candidate, p);
    if (q.is_zero()) return false;

    return compare(mul(p, q), n) == 0;
}

}  // namespace

std::optional<Bignum> wiener(const Bignum& n, const Bignum& e) {
    if (n.is_zero()) throw Error("the modulus must not be zero");
    if (e.is_zero()) throw Error("the public exponent must not be zero");

    // Convergents of e/n, built as the continued fraction is expanded:
    //   numerator_i = term_i * numerator_{i-1} + numerator_{i-2}
    // The numerator plays the part of k and the denominator of d in
    // e*d - k*phi = 1.
    Bignum previous_numerator;        // h(-2) = 0
    Bignum numerator(1);              // h(-1) = 1
    Bignum previous_denominator(1);   // k(-2) = 1
    Bignum denominator;               // k(-1) = 0

    Bignum a = e;
    Bignum b = n;

    while (!b.is_zero()) {
        const DivResult step = divmod(a, b);
        a = b;
        b = step.rem;

        Bignum next_numerator = add(mul(step.quot, numerator), previous_numerator);
        previous_numerator = numerator;
        numerator = next_numerator;

        Bignum next_denominator = add(mul(step.quot, denominator), previous_denominator);
        previous_denominator = denominator;
        denominator = next_denominator;

        const Bignum& k = numerator;
        const Bignum& d = denominator;
        if (k.is_zero() || d.is_zero()) continue;

        // phi = (e*d - 1) / k, and it has to divide exactly.
        const Bignum product = mul(e, d);
        if (compare(product, Bignum(1)) < 0) continue;
        const DivResult phi_step = divmod(sub(product, Bignum(1)), k);
        if (!phi_step.rem.is_zero()) continue;

        const Bignum phi = phi_step.quot;
        if (phi.is_zero() || compare(phi, n) > 0) continue;
        if (!phi_factors_n(n, phi)) continue;

        // Three checks passed; the last one is the one a user would do.
        if (!exponent_round_trips(n, e, d)) continue;
        return d;
    }

    return std::nullopt;
}

}  // namespace cryptrift
