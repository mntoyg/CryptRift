#include <cryptrift/score.hpp>

#include <cryptrift/bytes.hpp>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;
using cryptrift::english_score;
using cryptrift::from_string;
using cryptrift::printable_ratio;

void run_score_tests() {
    const Bytes english = from_string("the quick brown fox jumps over the lazy dog");
    const Bytes noise = Bytes({0x00, 0xFF, 0x01, 0xFE, 0x7F, 0x80, 0x02});

    CT_CHECK(english_score(english) > english_score(noise));
    CT_CHECK(english_score(english) > english_score(from_string("zzzzzzzzzzzzzzzzzzzz")));

    // Printable but not English: a candidate of digits must not outrank real
    // text, or a brute force will happily rank a numeric false positive first.
    CT_CHECK(english_score(english) > english_score(from_string("1234567890123456789012")));
    CT_CHECK(english_score(english) > english_score(from_string("!@#$%^&*()!@#$%^&*()!@")));

    // Empty input must be a defined score, never NaN: a NaN sorts
    // unpredictably and would scramble the whole candidate ranking.
    CT_CHECK_EQ(english_score(Bytes{}), 0.0);
    CT_CHECK_EQ(printable_ratio(Bytes{}), 0.0);
    CT_CHECK(english_score(Bytes{}) == english_score(Bytes{}));
    CT_CHECK(printable_ratio(Bytes{}) == printable_ratio(Bytes{}));

    // A single byte: no bigram to divide by.
    CT_CHECK(english_score(from_string("a")) == english_score(from_string("a")));

    CT_CHECK_EQ(printable_ratio(from_string("abc")), 1.0);
    CT_CHECK_EQ(printable_ratio(from_string("a\tb\nc\r")), 1.0);
    CT_CHECK(printable_ratio(Bytes({'a', 0x00})) < 1.0);
    CT_CHECK_EQ(printable_ratio(Bytes({0x00, 0x01})), 0.0);

    // Case folding: the same sentence shouted scores the same.
    CT_CHECK_EQ(english_score(from_string("the quick brown fox")),
                english_score(from_string("THE QUICK BROWN FOX")));
}
