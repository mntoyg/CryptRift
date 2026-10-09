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

}  // namespace cryptrift

#endif  // CRYPTRIFT_RSA_HPP
