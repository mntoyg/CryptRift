#include <cryptrift/bytes.hpp>
#include <cryptrift/error.hpp>

#include <sstream>
#include <string>

#include "ct_test.hpp"
#include "tests.hpp"

using cryptrift::Bytes;

void run_bytes_tests() {
    // A CTF blob is binary. An embedded NUL must survive the trip, which rules
    // out anything that treats the input as a C string.
    std::istringstream in(std::string("a\0b", 3));
    CT_CHECK_EQ(cryptrift::read_stream(in), Bytes({'a', 0x00, 'b'}));

    std::istringstream empty_input("");
    CT_CHECK_EQ(cryptrift::read_stream(empty_input), Bytes{});

    CT_CHECK_THROWS(cryptrift::read_file("no/such/file"), cryptrift::Error);

    CT_CHECK_EQ(cryptrift::to_string(cryptrift::from_string("hi")), std::string("hi"));
}
