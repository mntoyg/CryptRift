// A very small test harness: enough to assert, report and fail the build.
//
// It is deliberately not a framework. Tests are plain functions called from
// main.cpp; a failed check writes one line to stderr and bumps a counter, and
// the process exit code is what CTest reads. ct_selftest proves the counter
// actually works -- a harness that cannot fail would make every suite below it
// meaningless.
#ifndef CRYPTRIFT_TESTS_CT_TEST_HPP
#define CRYPTRIFT_TESTS_CT_TEST_HPP

#include <cstddef>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

namespace ct {

inline int& failure_counter() {
    static int count = 0;
    return count;
}

inline int failures() { return failure_counter(); }

inline void fail(const char* file, int line, const std::string& message) {
    ++failure_counter();
    std::cerr << file << ":" << line << ": FAILED " << message << "\n";
}

// show(value) -- a best-effort printable form, so a failure says what it saw.
//
// Three cases, picked at compile time: anything streamable prints itself;
// anything iterable prints its elements in braces; anything else prints a
// placeholder. Without the fallback, CT_CHECK_EQ would only compile for types
// that happen to have an operator<<.
template <typename T>
std::string show(const T& value);

namespace detail {

template <typename...>
using void_t = void;

template <typename T, typename = void>
struct is_streamable : std::false_type {};

template <typename T>
struct is_streamable<T, void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <typename T, typename = void>
struct is_iterable : std::false_type {};

template <typename T>
struct is_iterable<T, void_t<decltype(std::begin(std::declval<const T&>())),
                             decltype(std::end(std::declval<const T&>()))>> : std::true_type {};

// A byte is streamable, but streams as a glyph; in a crypto test suite the
// number is what you need to see.
inline std::string show_one(unsigned char byte) {
    static const char* digits = "0123456789abcdef";
    std::string out = "0x";
    out += digits[(byte >> 4) & 0x0F];
    out += digits[byte & 0x0F];
    return out;
}

template <typename T>
std::string show_dispatch(const T& value, std::true_type /*streamable*/) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

template <typename T>
std::string show_container(const T& value) {
    std::string out = "{";
    bool first = true;
    for (const auto& element : value) {
        if (!first) out += ", ";
        first = false;
        out += ct::show(element);
    }
    out += "}";
    return out;
}

template <typename T>
std::string show_dispatch(const T& value, std::false_type /*streamable*/) {
    if (is_iterable<T>::value) return show_container(value);
    return "<unprintable>";
}

}  // namespace detail

inline std::string show(unsigned char value) { return detail::show_one(value); }

template <typename T>
std::string show(const T& value) {
    // std::string is both streamable and iterable; streamable wins, which is
    // what you want to read.
    return detail::show_dispatch(value, detail::is_streamable<T>{});
}

}  // namespace ct

#define CT_CHECK(expr)                                                          \
    do {                                                                        \
        if (!(expr)) ct::fail(__FILE__, __LINE__, "CT_CHECK(" #expr ")");       \
    } while (0)

#define CT_CHECK_EQ(actual, expected)                                           \
    do {                                                                        \
        const auto& ct_actual_ = (actual);                                       \
        const auto& ct_expected_ = (expected);                                   \
        if (!(ct_actual_ == ct_expected_)) {                                     \
            ct::fail(__FILE__, __LINE__,                                         \
                     std::string("CT_CHECK_EQ(" #actual ", " #expected ")\n") +  \
                         "  actual:   " + ct::show(ct_actual_) + "\n" +          \
                         "  expected: " + ct::show(ct_expected_));               \
        }                                                                        \
    } while (0)

#define CT_CHECK_THROWS(expr, ExceptionType)                                    \
    do {                                                                        \
        int ct_state_ = 0;                                                       \
        try {                                                                    \
            (void)(expr);                                                        \
        } catch (const ExceptionType&) {                                         \
            ct_state_ = 1;                                                       \
        } catch (...) {                                                          \
            ct_state_ = 2;                                                        \
        }                                                                        \
        if (ct_state_ == 0)                                                      \
            ct::fail(__FILE__, __LINE__, "did not throw " #ExceptionType ": " #expr); \
        else if (ct_state_ == 2)                                                 \
            ct::fail(__FILE__, __LINE__, "threw the wrong type, wanted " #ExceptionType ": " #expr); \
    } while (0)

#endif  // CRYPTRIFT_TESTS_CT_TEST_HPP
