#include <cryptrift/classical.hpp>

#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <cstddef>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::affine_decrypt;
using cryptrift::affine_encrypt;
using cryptrift::caesar;
using cryptrift::crack_affine;
using cryptrift::crack_caesar;
using cryptrift::from_string;

void run_classical_tests() {
    CT_CHECK_EQ(caesar(from_string("attack at dawn"), 3), from_string("dwwdfn dw gdzq"));
    CT_CHECK_EQ(caesar(from_string("Hello, World!"), 13), from_string("Uryyb, Jbeyq!"));
    CT_CHECK_EQ(caesar(caesar(from_string("abc"), 5), -5), from_string("abc"));
    CT_CHECK_EQ(caesar(from_string("abc"), 26), from_string("abc"));   // a full turn
    CT_CHECK_EQ(caesar(from_string("abc"), 29), caesar(from_string("abc"), 3));
    CT_CHECK_EQ(caesar(from_string("abc"), -1), from_string("zab"));   // wraps downwards

    // Anything that is not an ASCII letter passes through untouched, including
    // the bytes of a UTF-8 character.
    CT_CHECK_EQ(caesar(from_string("a\xC3\xA9 1"), 1), from_string("b\xC3\xA9 1"));
    CT_CHECK_EQ(caesar(Bytes({0x00, 0xFF}), 5), Bytes({0x00, 0xFF}));
    CT_CHECK_EQ(caesar(Bytes{}, 5), Bytes{});

    CT_CHECK_EQ(affine_decrypt(affine_encrypt(from_string("the eagle has landed"), 5, 8), 5, 8),
                from_string("the eagle has landed"));
    CT_CHECK_EQ(affine_encrypt(from_string("abc"), 1, 3), caesar(from_string("abc"), 3));

    // A multiplier sharing a factor with 26 is not invertible: the map would
    // collapse letters together and could not be undone. That is a usage error,
    // not a silent no-op.
    CT_CHECK_THROWS(affine_encrypt(from_string("abc"), 13, 0), cryptrift::Error);
    CT_CHECK_THROWS(affine_encrypt(from_string("abc"), 0, 0), cryptrift::Error);
    CT_CHECK_THROWS(affine_encrypt(from_string("abc"), 2, 1), cryptrift::Error);
    CT_CHECK_THROWS(affine_decrypt(from_string("abc"), 13, 0), cryptrift::Error);

    const Bytes plain = from_string("the flag for this challenge is a classical cipher");

    const auto caesar_hits = crack_caesar(caesar(plain, 7), 0.9, 5);
    CT_CHECK(!caesar_hits.empty());
    CT_CHECK_EQ(caesar_hits.front().plaintext, plain);  // rank 1
    CT_CHECK_EQ(caesar_hits.front().b, 7);              // the encryption key, as applied
    CT_CHECK_EQ(caesar_hits.front().a, 1);
    CT_CHECK(caesar_hits.size() <= 5);

    const auto affine_hits = crack_affine(affine_encrypt(plain, 11, 4), 0.9, 5);
    CT_CHECK(!affine_hits.empty());
    CT_CHECK_EQ(affine_hits.front().plaintext, plain);
    CT_CHECK_EQ(affine_hits.front().a, 11);
    CT_CHECK_EQ(affine_hits.front().b, 4);

    // The whole keyspace: 12 multipliers coprime with 26, times 26 shifts.
    CT_CHECK_EQ(crack_affine(plain, 0.0, 0).size(), static_cast<std::size_t>(12 * 26));
    CT_CHECK_EQ(crack_caesar(plain, 0.0, 0).size(), static_cast<std::size_t>(26));

    CT_CHECK(crack_caesar(Bytes{}, 0.9, 5).empty());
    CT_CHECK(crack_affine(Bytes{}, 0.9, 5).empty());
    // A shift cipher cannot change which bytes are printable, so a blob of
    // control bytes has no candidate that clears the filter.
    CT_CHECK(crack_caesar(Bytes({0x00, 0x01, 0x02}), 0.9, 5).empty());
}
