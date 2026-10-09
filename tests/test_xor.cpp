#include <cryptrift/xor_tool.hpp>

#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <cstddef>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::apply_repeating;
using cryptrift::crack_single_byte;
using cryptrift::from_string;

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
