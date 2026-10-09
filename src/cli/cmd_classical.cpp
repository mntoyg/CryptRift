#include "cli/commands.hpp"
#include "cli/render.hpp"

#include <cryptrift/classical.hpp>
#include <cryptrift/codec.hpp>

#include <istream>
#include <ostream>
#include <vector>

namespace cryptrift {
namespace cli {
namespace {

Bytes input_of(const Args& args, std::istream& in) {
    return load_input(args, require_format(args, "--in-format", Format::raw), in);
}

int write_result(const Bytes& data, const Args& args, std::ostream& out) {
    const Format out_format = require_format(args, "--out-format", Format::raw);
    write_raw(out, from_string(encode(out_format, data)));
    return kOk;
}

// An empty candidate list is reported, never dressed up as success: exit 1, a
// word on stderr, and nothing on stdout.
int report(const std::vector<ClassicalCandidate>& hits, const Args& args, std::ostream& out,
           std::ostream& err) {
    if (hits.empty()) {
        err << "cryptrift: no candidate found\n";
        return kNoResult;
    }
    if (flag_quiet(args)) {
        write_raw(out, hits.front().plaintext);
        return kOk;
    }
    render_classical(out, hits, flag_top(args));
    return kOk;
}

}  // namespace

int cmd_caesar_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const int shift = require_int(args, "--shift");
    return write_result(caesar(input_of(args, in), shift), args, out);
}

int cmd_caesar_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err) {
    const Bytes data = input_of(args, in);
    return report(crack_caesar(data, flag_min_printable(args), flag_top(args)), args, out, err);
}

int cmd_affine_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const int multiplier = require_int(args, "--a");
    const int offset = require_int(args, "--b");
    return write_result(affine_encrypt(input_of(args, in), multiplier, offset), args, out);
}

int cmd_affine_decrypt(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const int multiplier = require_int(args, "--a");
    const int offset = require_int(args, "--b");
    return write_result(affine_decrypt(input_of(args, in), multiplier, offset), args, out);
}

int cmd_affine_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err) {
    const Bytes data = input_of(args, in);
    return report(crack_affine(data, flag_min_printable(args), flag_top(args)), args, out, err);
}

}  // namespace cli
}  // namespace cryptrift
