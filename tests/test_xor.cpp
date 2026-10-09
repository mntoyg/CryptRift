#include <cryptrift/xor_tool.hpp>

#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <algorithm>
#include <cstddef>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::apply_repeating;
using cryptrift::crack_repeating;
using cryptrift::crack_single_byte;
using cryptrift::crib_drag;
using cryptrift::guess_key_lengths;
using cryptrift::from_string;
using cryptrift::to_string;

void run_xor_tests() {
    CT_CHECK_EQ(apply_repeating(from_string("abc"), Bytes({0x00})), from_string("abc"));

    const Bytes data = from_string("hello world");
    const Bytes key = from_string("KEY");
    CT_CHECK_EQ(apply_repeating(apply_repeating(data, key), key), data);  // its own inverse
    CT_CHECK_EQ(apply_repeating(data, key).size(), data.size());

    // A key longer than the data is fine; only its prefix is used.
    CT_CHECK_EQ(apply_repeating(from_string("ab"), from_string("LONGKEY")),
                Bytes({'a' ^ 'L', 'b' ^ 'O'}));

    // An empty key would reach index % 0. It is a usage error, not a crash.
    CT_CHECK_THROWS(apply_repeating(data, Bytes{}), cryptrift::Error);
    CT_CHECK_THROWS(apply_repeating(Bytes{}, Bytes{}), cryptrift::Error);
    CT_CHECK_EQ(apply_repeating(Bytes{}, key), Bytes{});

    const Bytes plain = from_string("The flag is flag{xor_is_not_encryption}");
    const Bytes cipher = apply_repeating(plain, Bytes({0x5A}));

    const auto hits = crack_single_byte(cipher, 0.9, 10);
    CT_CHECK(!hits.empty());
    // Rank 1, not "somewhere in the top ten": anything weaker lets the scoring
    // rot without a test noticing.
    CT_CHECK_EQ(hits.front().plaintext, plain);
    CT_CHECK_EQ(hits.front().key, Bytes({0x5A}));
    CT_CHECK(hits.size() <= 10);
    for (std::size_t index = 1; index < hits.size(); ++index) {
        CT_CHECK(hits[index - 1].score >= hits[index].score);
    }

    // Found nothing is a result, not an error. The input matters: pairs that
    // differ in the high bit cannot both be printable under one key, however
    // the key is chosen, so no candidate can clear the filter. A short blob of
    // low bytes would not do -- {0x00, 0x01, 0x02} xor 0x41 is "A@C".
    CT_CHECK(crack_single_byte(Bytes({0x00, 0x80, 0x01, 0x81}), 0.99, 10).empty());
    CT_CHECK(!crack_single_byte(Bytes({0x00, 0x01, 0x02}), 0.99, 10).empty());

    // Empty input has nothing to crack, whatever the threshold. Checked at 0.0
    // too, because printable_ratio({}) is 0.0 and would otherwise pass the
    // filter and yield 256 empty "answers".
    CT_CHECK(crack_single_byte(Bytes{}, 0.9, 10).empty());
    CT_CHECK(crack_single_byte(Bytes{}, 0.0, 0).empty());

    // limit 0 means no limit: the whole keyspace comes back.
    CT_CHECK_EQ(crack_single_byte(cipher, 0.0, 0).size(), static_cast<std::size_t>(256));
    CT_CHECK_EQ(crack_single_byte(cipher, 0.0, 3).size(), static_cast<std::size_t>(3));
}

namespace {

// Long enough for block statistics to mean something: key-length detection
// compares consecutive blocks, so a few hundred bytes of real English is the
// realistic case a CTF presents.
Bytes prose() {
    return from_string(
        "The art of cryptanalysis is the art of noticing what does not belong. "
        "A repeating key leaves a rhythm in the ciphertext, and once the length "
        "of that rhythm is known the problem falls apart into many small "
        "problems, each of them a single byte wide. That is the whole trick, and "
        "it is why a stream must never reuse a key across two messages.");
}

}  // namespace

void run_xor_repeating_tests() {
    const Bytes plain = prose();
    const Bytes key = from_string("RIFT");
    const Bytes cipher = apply_repeating(plain, key);

    // The Hamming heuristic favours multiples of the real key length, because a
    // multiple decrypts just as cleanly: measured here it ranks 12, 20, 16, then
    // 4. So the honest assertion is that the leaders are multiples of 4, and
    // that 4 itself is in reach -- not that it comes first.
    const auto lengths = guess_key_lengths(cipher, cryptrift::KeyLenRange{2, 20}, 5);
    CT_CHECK(!lengths.empty());
    CT_CHECK_EQ(lengths.front() % 4, static_cast<std::size_t>(0));
    CT_CHECK(std::find(lengths.begin(), lengths.end(), static_cast<std::size_t>(4)) !=
             lengths.end());

    const auto hits = crack_repeating(cipher, cryptrift::KeyLenRange{2, 20}, 0.9, 5);
    CT_CHECK(!hits.empty());
    CT_CHECK_EQ(hits.front().key, key);
    CT_CHECK_EQ(hits.front().plaintext, plain);

    // A multiple of the real key length decrypts just as well -- "RIFTRIFT"
    // yields the same plaintext and the same score -- so the key is reduced to
    // its smallest period before being reported. Otherwise the answer would
    // depend on which multiple the heuristic happened to rank first.
    CT_CHECK_EQ(hits.front().key.size(), static_cast<std::size_t>(4));
    for (std::size_t index = 1; index < hits.size(); ++index) {
        CT_CHECK(hits[index].key != hits.front().key);  // no duplicate keys
    }

    // A range that excludes the real length still solves it: every multiple of
    // 4 decrypts correctly, and reducing the recovered key to its smallest
    // period turns "RIFTRIFT" back into "RIFT". Without that reduction the
    // plaintext would be right and the reported key wrong.
    const auto narrowed = crack_repeating(cipher, cryptrift::KeyLenRange{5, 20}, 0.9, 5);
    CT_CHECK(!narrowed.empty());
    CT_CHECK_EQ(narrowed.front().key, key);
    CT_CHECK_EQ(narrowed.front().plaintext, plain);

    // A short ciphertext is where over-fitting bites: with only 69 bytes, three
    // keys of 15 and 16 bytes scored above the real 4-byte key on raw English
    // score alone. The length penalty is what puts the real answer back on top.
    const Bytes short_plain =
        from_string("The art of cryptanalysis is the art of noticing what does not belong.");
    const auto short_hits =
        crack_repeating(apply_repeating(short_plain, key), cryptrift::KeyLenRange{2, 20}, 0.9, 5);
    CT_CHECK(!short_hits.empty());
    CT_CHECK_EQ(short_hits.front().key, key);
    CT_CHECK_EQ(short_hits.front().plaintext, short_plain);

    CT_CHECK(crack_repeating(Bytes{}, cryptrift::KeyLenRange{2, 20}, 0.9, 5).empty());
    // Data shorter than the smallest key length leaves nothing to measure.
    CT_CHECK(crack_repeating(from_string("ab"), cryptrift::KeyLenRange{8, 20}, 0.9, 5).empty());
    CT_CHECK(guess_key_lengths(from_string("ab"), cryptrift::KeyLenRange{8, 20}, 3).empty());

    const auto drag = crib_drag(cipher, from_string("the"));
    CT_CHECK_EQ(drag.size(), cipher.size() - 2);
    CT_CHECK_EQ(drag.front().offset, static_cast<std::size_t>(0));
    CT_CHECK_EQ(drag.front().key_fragment.size(), static_cast<std::size_t>(3));
    // At the offset where the crib really sits, the fragment is the key,
    // rotated to that position. Lowercase "the" first appears at offset 28,
    // and 28 % 4 == 0, so the fragment is the key's first three bytes.
    const std::size_t crib_at = cryptrift::to_string(plain).find("the");
    CT_CHECK_EQ(crib_at, static_cast<std::size_t>(28));
    CT_CHECK_EQ(drag[crib_at].key_fragment, Bytes({'R', 'I', 'F'}));

    CT_CHECK_THROWS(crib_drag(cipher, Bytes{}), cryptrift::Error);
    CT_CHECK(crib_drag(from_string("ab"), from_string("abcd")).empty());
    CT_CHECK_EQ(crib_drag(from_string("abcd"), from_string("abcd")).size(),
                static_cast<std::size_t>(1));
}
