// The one exception type in CryptRift.
//
// Error means the input was invalid: malformed hex, an affine multiplier that
// has no inverse, a modulus of zero. It does NOT mean an attack failed to find
// anything -- that is an empty result, not an exception, and the two are never
// conflated. The CLI maps Error to exit code 2 and an empty result to exit
// code 1.
#ifndef CRYPTRIFT_ERROR_HPP
#define CRYPTRIFT_ERROR_HPP

#include <stdexcept>
#include <string>

namespace cryptrift {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& what_arg) : std::runtime_error(what_arg) {}
};

}  // namespace cryptrift

#endif  // CRYPTRIFT_ERROR_HPP
