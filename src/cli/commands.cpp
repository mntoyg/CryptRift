#include "cli/commands.hpp"

namespace cryptrift {
namespace cli {

const std::vector<Command>& all_commands() {
    static const std::vector<Command> table = {
        {"base", "conv", "base conv [--in-format F] [--out-format F] [INPUT]",
         "Convert between raw, hex, b64, b32, bin and dec.", cmd_base_conv},
        {"xor", "apply", "xor apply (--key TEXT | --key-hex HEX) [INPUT]",
         "XOR with a repeating key. Its own inverse, so this also decrypts.", cmd_xor_apply},
        {"xor", "crack", "xor crack [--keylen-min N --keylen-max N] [-q] [--top N] [INPUT]",
         "Recover the key. Single-byte by default; name a key-length range for a repeating key.",
         cmd_xor_crack},
        {"xor", "crib", "xor crib --crib TEXT [INPUT]",
         "Drag a known plaintext across the ciphertext, showing the key each offset implies.",
         cmd_xor_crib},
        {"caesar", "apply", "caesar apply --shift N [INPUT]",
         "Shift letters by N. A negative shift decrypts.", cmd_caesar_apply},
        {"caesar", "crack", "caesar crack [-q] [--top N] [INPUT]",
         "Try all 26 shifts and rank them. The key is reported as it was applied.",
         cmd_caesar_crack},
        {"affine", "apply", "affine apply --a A --b B [INPUT]",
         "Encrypt with E(x) = (A*x + B) mod 26. A must be coprime with 26.", cmd_affine_apply},
        {"affine", "decrypt", "affine decrypt --a A --b B [INPUT]",
         "Decrypt with a known affine key.", cmd_affine_decrypt},
        {"affine", "crack", "affine crack [-q] [--top N] [INPUT]",
         "Try all 312 affine keys and rank them.", cmd_affine_crack},
        {"rsa", "params", "rsa params --p P --q Q --e E",
         "Derive n, phi and d from the factors.", cmd_rsa_params},
        {"rsa", "encrypt", "rsa encrypt --m M --e E --n N", "Compute m^e mod n.",
         cmd_rsa_encrypt},
        {"rsa", "decrypt", "rsa decrypt --c C (--d D --n N | --p P --q Q --e E)",
         "Decrypt with the private exponent, or with the factors.", cmd_rsa_decrypt},
        {"rsa", "smalle", "rsa smalle --c C --e E",
         "Recover m when m^e never wrapped n, by taking an exact e-th root.",
         cmd_rsa_smalle},
        {"rsa", "common-modulus",
         "rsa common-modulus --n N --e1 E1 --c1 C1 --e2 E2 --c2 C2",
         "Recover one message encrypted twice under one modulus with coprime exponents.",
         cmd_rsa_common_modulus},
        {"rsa", "wiener", "rsa wiener --n N --e E",
         "Recover a private exponent that is small relative to n. Reports nothing if it cannot.",
         cmd_rsa_wiener},
    };
    return table;
}

const Command* find_command(std::string_view group, std::string_view command) {
    for (const Command& entry : all_commands()) {
        if (group == entry.group && command == entry.command) return &entry;
    }
    return nullptr;
}

}  // namespace cli
}  // namespace cryptrift
