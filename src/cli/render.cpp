#include "cli/render.hpp"

#include <ostream>

namespace cryptrift {
namespace cli {

void write_raw(std::ostream& out, const Bytes& data) {
    if (data.empty()) return;
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

}  // namespace cli
}  // namespace cryptrift
