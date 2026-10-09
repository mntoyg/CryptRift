# CryptRift

[![CI](https://github.com/mntoyg/CryptRift/actions/workflows/ci.yml/badge.svg)](https://github.com/mntoyg/CryptRift/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](https://en.cppreference.com/w/cpp/17)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](CMakeLists.txt)

A command-line C++ toolkit for common CTF crypto tasks — XOR, affine, RSA
helpers, base conversions — to speed up challenge solving and to strengthen
practical cryptography skills.

It does not just transform with a key you already have. **It recovers the key.**

```console
$ cryptrift xor crack -q --in-format hex 0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427
The flag is flag{xor_is_not_encryption}
```

No dependencies — not even a big-integer library. The arbitrary-precision
arithmetic behind the RSA helpers is written in this repository, which is half
the reason it exists.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Needs a C++17 compiler and CMake 3.14 or newer. CI builds it on Linux with GCC
and on Windows with MSVC, warnings as errors.

## Three things it is actually for

**Crack a single-byte XOR from a hex blob.** The default output is a ranked
table, so you can see why the winner won:

```console
$ cryptrift xor crack --in-format hex --top 3 0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427
rank  key                   score  plaintext
   1  5a                   138.18  The flag is flag{xor_is_not_encryption}
   2  50                   135.53  ^bo*lfkm*cy*lfkmqrexUcyUde~Uodixsz~cedw
   3  70                   135.53  ~BO.LFKM.CY.LFKMQREXuCYuDE^uODIXSZ^CEDW
```

Add `-q` and you get only the winning plaintext, as raw bytes, so it pipes into
whatever comes next.

**Break a classical cipher without counting letters by hand.** All 312 affine
keys, scored and ranked:

```console
$ echo -n "Wklv lv d whvw phvvdjh iru wkh fudfnhu" | cryptrift affine crack -q
This is a test message for the cracker
```

**Pull a flag out of an RSA number.** Here the message was small enough that
`m^e` never wrapped the modulus, so the ciphertext is a perfect cube:

```console
$ cryptrift rsa smalle --c 534362316273970181549588003507266739265499754799160081099504986457180500546068085545023534181 --e 3 --out-format raw
flag{small_e}
```

## Commands

| Command | What it does |
|---|---|
| `base conv` | Convert between `raw`, `hex`, `b64`, `b32`, `bin` and `dec` |
| `xor apply` | XOR with a repeating key — its own inverse, so it also decrypts |
| `xor crack` | Recover the key. Single-byte by default; `--keylen-min/--keylen-max` for a repeating key |
| `xor crib` | Drag a known plaintext across the ciphertext, showing the key each offset implies |
| `caesar apply` / `caesar crack` | Shift by N, or try all 26 |
| `affine apply` / `affine decrypt` / `affine crack` | `E(x) = (a·x + b) mod 26`, or try all 312 keys |
| `rsa params` | Derive `n`, `phi` and `d` from the factors |
| `rsa encrypt` / `rsa decrypt` | `m^e mod n`, and back with `d` or with `p q e` |
| `rsa smalle` | Recover `m` when `m^e` never wrapped `n` |
| `rsa common-modulus` | One message, one modulus, two coprime exponents |
| `rsa wiener` | Recover a private exponent that is small relative to `n` |
| `analyze` | Length, printable share, coincidence index, likely encodings |

Full flags and more examples: [docs/usage.md](docs/usage.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Produced a result |
| `1` | Ran correctly and **found nothing** |
| `2` | Usage or input error |

The middle one is the point. An attack that comes up empty says so on stderr and
exits non-zero; it never prints an empty table and calls it success. Every attack
that recovers a key verifies that key before reporting it — Wiener's, for
instance, puts each candidate through three independent checks and reports
nothing when they all fail, rather than handing back the least-wrong guess.

A cracker that reports success while holding garbage is worse than no cracker at
all, because you act on it. Most of the test suite exists to prevent exactly
that.

## What this is not

Deliberately absent from v0.1.0: no network access (no factordb lookups), no
hashing, no block-cipher or padding-oracle tooling, no Vigenère, no substitution
solver, no colour output, no config file.

**And it is not a security library.** The big-integer arithmetic here is
schoolbook and not constant-time, nothing is padding-aware, and textbook RSA is
implemented exactly as textbook RSA. It is built for solving puzzles and for
understanding how the mathematics works. Do not protect anything with it.

## Design

The architecture, the module dependency order, and the rule that `src/core/`
never touches `argv`, the standard streams or `exit` are in
[docs/design.md](docs/design.md), with the full reasoning in
[docs/superpowers/specs/2026-10-09-cryptrift-design.md](docs/superpowers/specs/2026-10-09-cryptrift-design.md).

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). The short version is that a
new attack ships with two tests — one proving it solves a case it should, and one
proving it refuses a case it cannot.

## Licence

MIT — see [LICENSE](LICENSE).
