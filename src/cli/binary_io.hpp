// Windows opens the standard streams in text mode, where a 0x0A on the way out
// becomes 0x0D 0x0A and a 0x1A on the way in ends the stream. Either one
// silently corrupts a recovered plaintext, so both get switched to binary
// before anything is read or written.
#ifndef CRYPTRIFT_CLI_BINARY_IO_HPP
#define CRYPTRIFT_CLI_BINARY_IO_HPP

namespace cryptrift {
namespace cli {

void set_stdio_binary();

}  // namespace cli
}  // namespace cryptrift

#endif  // CRYPTRIFT_CLI_BINARY_IO_HPP
