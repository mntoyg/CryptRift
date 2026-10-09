// RSA helpers, and the attacks that make a CTF challenge fall over.
//
// The rule this header exists to state: every attack verifies its own result
// before returning it. An attack that reports a key it never checked is worse
// than one that gives up, because the user acts on it. So each attack returns
// an optional and answers nothing rather than guessing, and "found nothing" is
// an ordinary result, not an error.
//
// None of this is constant-time or padding-aware. It is textbook RSA for
// solving puzzles, not a library for protecting anything.
#ifndef CRYPTRIFT_RSA_HPP
#define CRYPTRIFT_RSA_HPP

#include <cryptrift/bignum.hpp>

#include <cstdint>
#include <optional>

namespace cryptrift {

struct KeyParams {
    Bignum n;
    Bignum phi;
    Bignum d;
};

// Throws Error when p or q is below 2, when they are equal, or when e shares a
// factor with phi -- in that last case there is no private exponent at all, and
// reporting one would be a fiction.
KeyParams params(const Bignum& p, const Bignum& q, const Bignum& e);

Bignum encrypt(const Bignum& message, const Bignum& e, const Bignum& n);
Bignum decrypt(const Bignum& ciphertext, const Bignum& d, const Bignum& n);

// Derives d from the factors first. Convenient when a challenge hands over p
// and q rather than d.
Bignum decrypt_with_primes(const Bignum& ciphertext, const Bignum& p, const Bignum& q,
                           const Bignum& e);

// Recovers the message when it was small enough that m^e never wrapped the
// modulus, so the ciphertext is a perfect e-th power.
//
// Returns nothing when the ciphertext is not a perfect power: the inputs were
// well formed, the attack simply does not apply. Returning the floor of the
// root would be a confident wrong answer, which is the one outcome this file
// is written to prevent. Throws Error only when e is zero.
std::optional<Bignum> small_e_root(const Bignum& ciphertext, std::uint32_t e);

// One modulus, two coprime exponents, the same message: recovers it without
// either private key.
//
// Throws Error when the modulus is zero, when the exponents share a factor (the
// attack cannot be built then, so the caller asked for the wrong thing), or
// when the recovered value fails to re-encrypt to the first ciphertext -- which
// means the two ciphertexts were not a genuine pair, and a number arrived here
// that only looks like an answer.
Bignum common_modulus(const Bignum& n, const Bignum& e1, const Bignum& c1, const Bignum& e2,
                      const Bignum& c2);

}  // namespace cryptrift

#endif  // CRYPTRIFT_RSA_HPP
