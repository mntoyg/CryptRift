# CryptRift — Design

- **Date:** 2026-10-09
- **Status:** approved (design), pending implementation plan
- **Repo:** https://github.com/mntoyg/CryptRift (public, MIT)

## 1. Purpose

A command-line C++ toolkit for common CTF crypto tasks — XOR, affine, RSA
helpers, base conversions — to speed up challenge solving and to strengthen
practical cryptography skills.

Two goals, in this order:

1. **Speed during a CTF.** When a challenge drops a blob of hex, the answer
   should be one command away. The tool does not just transform with a key you
   already know; it recovers the key.
2. **Understanding.** The number theory is written here, not linked in from a
   library. Writing `modpow`, `modinv` and Wiener's attack by hand is the point.

### Success criteria

- `cryptrift xor crack` on a single-byte-XOR CTF ciphertext prints the correct
  plaintext at **rank 1**, not merely somewhere in the list.
- `cryptrift rsa` handles a realistic CTF modulus (hundreds of bits), not just
  textbook 8-bit examples.
- Output is pleasant to read interactively *and* pipeable: `-q` emits raw bytes
  so `cryptrift xor crack -q f | base64 -d` works.
- An attack that finds nothing says so and exits non-zero. It never prints a
  confident wrong answer.
- `ctest` passes on Linux and Windows in CI with `-Wall -Wextra -Werror`.

### Non-goals for v1

No network access (no factordb lookups), no colour output, no config file, no
Vigenere, no hashing, no block-cipher or padding-oracle tooling, no GUI. These
are deliberately deferred; none of them are needed for the four areas above.

## 2. Decisions and rationale

| Decision | Choice | Why |
|---|---|---|
| Structure | Core static library + thin CLI | Attacks get tested as function calls, not by shelling out to a binary and grepping stdout |
| Big integers | Our own bignum, in-repo | Zero dependencies, builds anywhere, and the number theory is the learning goal |
| Binary layout | One binary with subcommands | Conventional (`git`, `openssl`); one place for shared flags and help |
| Dependencies | None — not even on AlgoVault | An open-source CLI should not drag in a submodule |
| Language | C++17 | Matches AlgoVault; widest compiler support |
| Output | Human table by default, `-q` for raw | One scoring engine, two renderers: usable by a human and by a pipeline |
| Test runner | Small in-repo header, driven by CTest | Matches AlgoVault; no external framework to install |

## 3. Architecture

```
CryptRift/
├── CMakeLists.txt            # C++17; targets: cryptrift_core, cryptrift, ct_tests
├── LICENSE                   # MIT
├── README.md                 # badges, quick start, command table
├── CONTRIBUTING.md
├── .gitignore
├── .github/workflows/ci.yml  # ubuntu-latest + windows-latest
├── include/cryptrift/        # public headers of the core library
│   ├── error.hpp  bytes.hpp  codec.hpp  score.hpp
│   ├── xor_tool.hpp  classical.hpp
│   └── bignum.hpp  rsa.hpp  analyze.hpp
├── src/core/                 # implementation: no I/O, no printing, ever
├── src/cli/                  # main.cpp, args, render, cmd_*.cpp
├── tests/                    # ct_test.hpp + one file per module
└── docs/                     # design.md, usage.md
```

**The one hard rule:** `src/core/` never reads `argv`, never touches `std::cin`
or `std::cout`, and never calls `exit`. Core functions take values and return
values or throw. Everything the user sees is produced in `src/cli/`.

That rule is what makes the test suite meaningful: every attack is exercised
directly, with structured results to assert on.

## 4. Modules

Each module below answers: what it does, what it depends on, and how you use it.

### 4.1 `error` — the one exception type

`cryptrift::Error : std::runtime_error`. Thrown for invalid input only (see §6).
Depends on nothing.

### 4.2 `bytes` — the data type and input sources

- `using Bytes = std::vector<std::uint8_t>;`
- `Bytes read_input(const InputSpec&)` — from a literal argument, a file, or
  stdin. Binary-safe on Windows (stdin switched to binary mode).

No interpretation of content. Depends on `error`.

### 4.3 `codec` — representations

`Format { raw, hex, b64, b32, bin, dec }` with `decode(Format, string) -> Bytes`
and `encode(Format, Bytes) -> string`.

`raw` is bytes as-is; `hex`, `b64`, `b32` and `bin` are the obvious
character-per-group encodings. `dec` is the odd one out: it treats the whole
input as a **single non-negative big-endian integer written in decimal**, which
is how RSA moduli and ciphertexts arrive in challenges. Leading zeroes in `dec`
are not preserved, because the value, not the padding, is what it denotes.

Strict: bad characters, odd-length hex and bad padding throw `Error` rather than
being silently skipped. A CTF blob that fails to decode is information, so it
must not be quietly repaired.

Depends on `error`. Used by every command.

### 4.4 `score` — how English-like is this?

`double english_score(const Bytes&)`, higher is better. Combines:

- printable-ASCII ratio, with a hard penalty for control bytes,
- chi-squared distance from English letter frequency,
- a small bigram bonus to separate near-ties.

This module decides the quality of every brute-force result, so it gets its own
tests with known-good and known-garbage inputs.

Depends on `bytes`.

### 4.5 `xor_tool`

- `Bytes apply_repeating(Bytes data, Bytes key)` — also covers single-byte.
- `std::vector<Candidate> crack_single_byte(Bytes, std::size_t limit)` — all 256
  keys, scored, sorted descending.
- `std::vector<Candidate> crack_repeating(Bytes, KeyLenRange)` — guess key
  length by normalised Hamming distance / index of coincidence, then solve each
  column as single-byte XOR.
- `std::vector<CribHit> crib_drag(Bytes cipher, Bytes crib)` — every offset,
  with the key fragment each produces.

`Candidate { Bytes key; Bytes plaintext; double score; }`

Depends on `bytes`, `score`.

### 4.6 `classical`

- `caesar(Bytes, int shift)`, `affine_encrypt/decrypt(Bytes, int a, int b)`
  over A–Z/a–z, leaving other bytes untouched.
- `crack_caesar`, `crack_affine` — brute force the whole keyspace, scored and
  ranked. `a` must be coprime with 26; a non-invertible `a` passed explicitly is
  an `Error`, not a silent no-op.

Depends on `bytes`, `score`.

### 4.7 `bignum` — arbitrary-precision unsigned integer

Base 2^32 limbs in a `std::vector<std::uint32_t>`, little-endian.

- compare, add, subtract (throws on negative result), schoolbook multiply,
  `divmod`, shifts,
- `modpow` (square and multiply), `modinv` (extended Euclid, throws when
  `gcd != 1`), `gcd`,
- `iroot(k)` — floor integer k-th root by Newton iteration, plus an exactness
  flag,
- parse and print in hex and decimal.

The largest piece of work and the one where a silent wrong answer is most
damaging, so it carries the heaviest test burden (§7).

Depends on `error` only — deliberately. Swapping in faster multiplication later
must not touch `rsa`.

### 4.8 `rsa`

All over `bignum`:

- `params(p, q, e) -> {n, phi, d}`
- `encrypt(m, e, n)`, `decrypt(c, d, n)`, and decrypt-from-`p,q,e`
- `small_e_root(c, e) -> optional<Bignum>` — recover `m` when `m^e < n`
  (unpadded, tiny exponent). No exact `e`-th root is a *no result*, not an error:
  the inputs were well-formed, the attack simply does not apply.
- `common_modulus(n, e1, c1, e2, c2)` — `gcd(e1, e2) != 1` is an `Error`: the
  caller asked for an attack these exponents cannot support, which is a usage
  mistake rather than a failed search.
- `wiener(n, e) -> optional<Bignum>` — continued-fraction attack on small `d`

**Every attack verifies its own result before returning it.** Wiener returns a
`d` only after confirming it round-trips a probe message mod `n`; otherwise it
returns nothing. A recovered key that was never checked is the failure mode this
whole project must avoid.

Depends on `bignum`, `error`.

### 4.9 `analyze`

Frequency table, index of coincidence, printable ratio, and a guess at the input
encoding (looks like hex? base64?). Read-only reconnaissance for an unknown blob.

Depends on `bytes`, `codec`, `score`.

## 5. CLI contract

```
cryptrift <group> <command> [options] [input]

cryptrift base    conv    --in-format hex --out-format b64 4d7a
cryptrift xor     apply   --key-hex 1f data.bin
cryptrift xor     crack   --in-format hex 1c0111001f010100
cryptrift xor     crib    --crib "flag{" cipher.txt
cryptrift affine  crack   "Wklv lv d whvw"
cryptrift caesar  apply   --shift 3 "attack at dawn"
cryptrift rsa     params  --p 61 --q 53 --e 17
cryptrift rsa     wiener  --n <hex-or-dec> --e <hex-or-dec>
cryptrift analyze         cipher.txt
cryptrift help [group]
cryptrift --version
```

- **Input:** a positional value, or `--in FILE`, or stdin when the positional is
  absent or `-`.
- **Formats:** `--in-format` / `--out-format` take `raw|hex|b64|b32|bin|dec`,
  default `raw`.
- **Output:** crack commands print a ranked table (rank, key, score, preview).
  `-q` / `--quiet` prints only the best result's bytes, raw, so it pipes.
  `--top N` sets how many candidates to show (default 10).
- **Keys:** `xor apply` takes exactly one of `--key` (raw text) or `--key-hex`.
  Giving both, or neither, is a usage error.
- **Candidate filter:** a brute force keeps only candidates whose printable-ASCII
  ratio clears `--min-printable` (default 0.9), then ranks what survives by
  score. `--min-printable 0` keeps everything. When nothing survives, the result
  is empty and exit code 1 applies — the filter is what makes "found nothing" a
  reachable, testable state rather than a theoretical one.
- **Diagnostics** go to stderr, prefixed `cryptrift: `. Never to stdout, so
  stdout stays clean for pipes.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success — a result was produced |
| 1 | Ran correctly, found nothing (no candidate passed, attack not applicable) |
| 2 | Usage or input error (unknown command, bad hex, non-invertible `a`) |

### Data flow

`argv` → args parser → `codec::decode` → core function → result struct →
renderer (table or raw bytes) → stdout.

## 6. Error handling

Two distinct situations that must never be conflated:

**Invalid input** — malformed hex, an affine `a` sharing a factor with 26,
`modinv` where `gcd != 1`, an unreadable file. The core throws
`cryptrift::Error`. `main` catches at the top level, writes
`cryptrift: <message>` to stderr, exits **2**. No partial output on stdout.

**Attack found nothing** — brute force where no candidate clears the threshold,
Wiener against a key it cannot break. This is *not* an exception; it is an empty
result. The CLI prints `no candidate found` to stderr and exits **1**.

The distinction matters because the recurring bug shape in tooling like this is a
control that reports itself successful while having done nothing. A cracker must
not print an empty table and exit 0, and an attack must not return an unverified
key. Both cases get explicit tests.

## 7. Testing

A small in-repo header, `tests/ct_test.hpp`, providing `CHECK`, `CHECK_EQ`,
`CHECK_THROWS`, a failure count, and a non-zero exit on failure. One test binary
registered with CTest. No external test framework.

Where the effort goes:

- **`bignum`** — cross-check add, sub, mul and divmod against `__int128` across
  thousands of pseudo-random pairs with a fixed seed, plus known RSA vectors with
  published answers. Exercise carry and borrow edges: limb boundaries, zero,
  one-limb, equal operands, divisor longer than dividend.
- **`codec`** — round-trip fuzz for all formats, plus the RFC 4648 vectors.
- **`xor` and `classical` crackers** — known ciphertexts must recover the exact
  plaintext at **rank 1**. Asserting "somewhere in the top 10" would let scoring
  rot unnoticed.
- **`rsa`** — a full params/encrypt/decrypt cycle at realistic size; Wiener
  against a key with small `d` (must succeed) *and* against a safe key (must
  return nothing, not a wrong `d`).
- **Negative tests, one per guard** — the ones that must throw `Error`: empty
  input, odd-length hex, non-base64 characters, affine `a = 13`, `modinv` with a
  shared factor, subtraction going negative, `common_modulus` with
  `gcd(e1, e2) != 1`, `xor apply` with both `--key` and `--key-hex`.
- **No-result tests** — the ones that must return empty rather than throw or
  guess: `small_e_root` where no exact root exists, `wiener` on a safe key, and a
  brute force whose every candidate falls below `--min-printable`.
- **CLI smoke tests** — exit codes 0, 1 and 2 each produced on purpose, and `-q`
  output byte-exact.

**CI:** GitHub Actions on `ubuntu-latest` and `windows-latest` — configure,
build, `ctest --output-on-failure` — with `-Wall -Wextra -Werror` (`/W4 /WX` on
MSVC) enabled for the CI build.

## 8. Milestones

| # | Work | Done means |
|---|---|---|
| M1 | Repo skeleton, CMake, CI, `error`, `bytes`, `codec`, `base conv` | Repo is public with green CI; hex ↔ base64 conversion works from the shell |
| M2 | `score`, all of `xor_tool`, table and `-q` renderers | The most-used CTF path works end to end |
| M3 | `classical` — Caesar and affine, apply and crack | Full-keyspace crack ranks the right answer first |
| M4 | `bignum` with its full test suite | Cross-checks against `__int128` pass |
| M5 | `rsa` — params, encrypt/decrypt, small-e, common modulus, Wiener | Realistic-size key handled; Wiener refuses a key it cannot break |
| M6 | `analyze`, README, `docs/usage.md`, tag `v0.1.0` | First release |

Pushed from M1 onward so CI runs against real commits from the start, rather
than one large dump at the end.

## 9. Risks

- **Bignum correctness.** Mitigated by differential testing against `__int128`
  and by keeping `rsa` dependent only on `bignum`'s public surface.
- **Scoring quality.** A weak `english_score` makes every cracker look broken.
  Mitigated by rank-1 assertions on real ciphertexts.
- **Windows binary I/O.** Text-mode stdin corrupts binary input on Windows;
  `bytes` sets binary mode explicitly and CI builds on Windows to keep it honest.
- **Scope creep.** The §1 non-goals list is the guard; anything on it waits for
  v0.2.0.
