#include "cli/commands.hpp"
#include "cli/render.hpp"

#include <cryptrift/codec.hpp>
#include <cryptrift/error.hpp>
#include <cryptrift/xor_tool.hpp>

#include <iomanip>
#include <istream>
#include <string>
#include <ostream>

namespace cryptrift {
namespace cli {
namespace {

// Exactly one of --key (text) or --key-hex. Neither is a missing key and both
// is an ambiguous one; either way the user meant something specific that did
// not arrive.
Bytes require_key(const Args& args) {
    const bool has_text = has_flag(args, "--key");
    const bool has_hex = has_flag(args, "--key-hex");

    if (has_text && has_hex) throw Error("give either --key or --key-hex, not both");
    if (!has_text && !has_hex) throw Error("missing required option --key or --key-hex");

    const Bytes key = has_text ? decode(Format::raw, args.flags.at("--key"))
                               : decode(Format::hex, args.flags.at("--key-hex"));
    if (key.empty()) throw Error("xor key must not be empty");
    return key;
}

// Reports an empty candidate list honestly: exit 1, a word on stderr, and
// nothing on stdout. A table with no rows and exit 0 would read as success.
int render_or_report(const std::vector<Candidate>& hits, const Args& args, std::ostream& out,
                     std::ostream& err) {
    if (hits.empty()) {
        err << "cryptrift: no candidate found\n";
        return kNoResult;
    }
    if (flag_quiet(args)) {
        write_raw(out, hits.front().plaintext);
        return kOk;
    }
    render_candidates(out, hits, flag_top(args));
    return kOk;
}

}  // namespace

int cmd_xor_apply(const Args& args, std::istream& in, std::ostream& out, std::ostream&) {
    const Format in_format = require_format(args, "--in-format", Format::raw);
    const Format out_format = require_format(args, "--out-format", Format::raw);
    const Bytes key = require_key(args);
    const Bytes data = load_input(args, in_format, in);

    write_raw(out, from_string(encode(out_format, apply_repeating(data, key))));
    return kOk;
}

int cmd_xor_crack(const Args& args, std::istream& in, std::ostream& out, std::ostream& err) {
    const Format in_format = require_format(args, "--in-format", Format::raw);
    const Bytes data = load_input(args, in_format, in);
    const double min_printable = flag_min_printable(args);
    const std::size_t top = flag_top(args);

    // Single-byte by default, which is the common CTF case. Naming a key-length
    // range is how the user asks for the repeating-key search.
    const bool repeating = has_flag(args, "--keylen-min") || has_flag(args, "--keylen-max");
    if (!repeating) {
        return render_or_report(crack_single_byte(data, min_printable, top), args, out, err);
    }

    KeyLenRange range;
    range.min = flag_size(args, "--keylen-min", range.min);
    range.max = flag_size(args, "--keylen-max", range.max);
    if (range.min == 0) throw Error("--keylen-min must be at least 1");
    if (range.max < range.min) throw Error("--keylen-max must not be below --keylen-min");
    // Two blocks of that length have to fit, or there is nothing to measure.
    if (range.min > data.size() / 2) {
        throw Error("--keylen-min is too large for " + std::to_string(data.size()) +
                    " bytes of input; it must not exceed half of it");
    }

    return render_or_report(crack_repeating(data, range, min_printable, top), args, out, err);
}

int cmd_xor_crib(const Args& args, std::istream& in, std::ostream& out, std::ostream& err) {
    const Format in_format = require_format(args, "--in-format", Format::raw);
    const Format crib_format = require_format(args, "--crib-format", Format::raw);
    const Bytes crib = decode(crib_format, require(args, "--crib"));
    const Bytes data = load_input(args, in_format, in);

    const std::vector<CribHit> hits = crib_drag(data, crib);
    if (hits.empty()) {
        err << "cryptrift: the crib is longer than the ciphertext\n";
        return kNoResult;
    }

    const std::size_t top = flag_top(args);
    const std::size_t shown = (top == 0 || top > hits.size()) ? hits.size() : top;
    out << "offset  key fragment          as text\n";
    for (std::size_t index = 0; index < shown; ++index) {
        out << std::setw(6) << hits[index].offset << "  " << std::left << std::setw(20)
            << encode(Format::hex, hits[index].key_fragment) << std::right
            << preview(hits[index].key_fragment, 32) << "\n";
    }
    return kOk;
}

}  // namespace cli
}  // namespace cryptrift
