#include "cli/commands.hpp"
#include "cli/render.hpp"

#include <cryptrift/bignum.hpp>
#include <cryptrift/error.hpp>
#include <cryptrift/rsa.hpp>

#include <optional>
#include <ostream>

namespace cryptrift {
namespace cli {
namespace {

// Decimal, or hex with an explicit 0x. No guessing: a bare "41" is forty-one,
// not 0x41, because an RSA modulus quoted without a prefix is always decimal.
Bignum flag_bignum(const Args& args, const std::string& flag) {
    const std::string text = require(args, flag);
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return Bignum::from_hex(text);
    }
    return Bignum::from_dec(text);
}

// An RSA result is a number, so the default output here is decimal rather than
// the global raw default -- raw would spray unprintable bytes by default.
// --out-format raw is what turns a recovered message back into a flag.
int write_number(const Bignum& value, const Args& args, std::ostream& out) {
    const Format format = require_format(args, "--out-format", Format::dec);
    switch (format) {
        case Format::dec:
            out << value.to_dec() << "\n";
            return kOk;
        case Format::hex:
            out << value.to_hex() << "\n";
            return kOk;
        case Format::raw:
            write_raw(out, value.to_bytes_be());
            return kOk;
        default:
            throw Error("rsa output supports dec, hex or raw");
    }
}

// An attack that did not apply: exit 1, a word on stderr, nothing on stdout.
int report_missing(const char* what, std::ostream& err) {
    err << "cryptrift: no " << what << " found\n";
    return kNoResult;
}

}  // namespace

int cmd_rsa_params(const Args& args, std::istream&, std::ostream& out, std::ostream&) {
    const KeyParams key = params(flag_bignum(args, "--p"), flag_bignum(args, "--q"),
                                 flag_bignum(args, "--e"));
    out << "n   = " << key.n.to_dec() << "\n"
        << "phi = " << key.phi.to_dec() << "\n"
        << "d   = " << key.d.to_dec() << "\n";
    return kOk;
}

int cmd_rsa_encrypt(const Args& args, std::istream&, std::ostream& out, std::ostream&) {
    const Bignum message = flag_bignum(args, "--m");
    const Bignum e = flag_bignum(args, "--e");
    const Bignum n = flag_bignum(args, "--n");
    return write_number(encrypt(message, e, n), args, out);
}

int cmd_rsa_decrypt(const Args& args, std::istream&, std::ostream& out, std::ostream&) {
    const Bignum ciphertext = flag_bignum(args, "--c");

    if (has_flag(args, "--d")) {
        const Bignum n = flag_bignum(args, "--n");
        return write_number(decrypt(ciphertext, flag_bignum(args, "--d"), n), args, out);
    }
    if (has_flag(args, "--p") && has_flag(args, "--q") && has_flag(args, "--e")) {
        return write_number(decrypt_with_primes(ciphertext, flag_bignum(args, "--p"),
                                                flag_bignum(args, "--q"),
                                                flag_bignum(args, "--e")),
                            args, out);
    }
    throw Error("give either --d --n, or --p --q --e");
}

int cmd_rsa_smalle(const Args& args, std::istream&, std::ostream& out, std::ostream& err) {
    const Bignum ciphertext = flag_bignum(args, "--c");
    // Range-checked rather than narrowed: 4294967297 would otherwise become 1,
    // and iroot(c, 1) returns c as an exact root, so the tool would hand the
    // ciphertext back as if it were the message.
    const std::uint32_t e = require_u32(args, "--e");
    if (e == 0) throw Error("--e must be a positive whole number");

    const std::optional<Bignum> message = small_e_root(ciphertext, e);
    if (!message.has_value()) {
        // The ciphertext is not a perfect power, so the attack does not apply.
        // Reporting the floor of the root would be a confident wrong answer.
        return report_missing("exact root", err);
    }
    return write_number(*message, args, out);
}

int cmd_rsa_common_modulus(const Args& args, std::istream&, std::ostream& out, std::ostream&) {
    const Bignum n = flag_bignum(args, "--n");
    const Bignum e1 = flag_bignum(args, "--e1");
    const Bignum c1 = flag_bignum(args, "--c1");
    const Bignum e2 = flag_bignum(args, "--e2");
    const Bignum c2 = flag_bignum(args, "--c2");
    return write_number(common_modulus(n, e1, c1, e2, c2), args, out);
}

int cmd_rsa_wiener(const Args& args, std::istream&, std::ostream& out, std::ostream& err) {
    const Bignum n = flag_bignum(args, "--n");
    const Bignum e = flag_bignum(args, "--e");

    const std::optional<Bignum> d = wiener(n, e);
    if (!d.has_value()) return report_missing("private exponent", err);
    return write_number(*d, args, out);
}

}  // namespace cli
}  // namespace cryptrift
