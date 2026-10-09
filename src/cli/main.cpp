#include "cli/args.hpp"
#include "cli/binary_io.hpp"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    // Before any read or write: see binary_io.hpp.
    cryptrift::cli::set_stdio_binary();

    const std::vector<std::string> tail(argv + 1, argv + argc);
    return cryptrift::cli::run(tail, std::cin, std::cout, std::cerr);
}
