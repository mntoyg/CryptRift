// How English-like is this blob?
//
// Every brute force in CryptRift ends up here: the attack produces candidates,
// this decides which one the user sees first. A weak score makes every cracker
// look broken, so the crackers' tests assert the right answer lands at rank 1
// rather than merely somewhere in the list.
#ifndef CRYPTRIFT_SCORE_HPP
#define CRYPTRIFT_SCORE_HPP

#include <cryptrift/bytes.hpp>

namespace cryptrift {

// Share of bytes that are printable ASCII, counting tab, newline and carriage
// return. Exactly 0.0 for empty input -- not NaN, because a NaN would sort
// unpredictably and scramble a candidate ranking.
double printable_ratio(const Bytes& data);

// Higher is more English-like. Exactly 0.0 for empty input. The absolute value
// carries no meaning; only comparisons between candidates do.
double english_score(const Bytes& data);

}  // namespace cryptrift

#endif  // CRYPTRIFT_SCORE_HPP
