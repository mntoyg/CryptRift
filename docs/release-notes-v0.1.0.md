# CryptRift v0.1.0

First release. A dependency-free C++17 command-line toolkit for common CTF
crypto tasks, built to recover keys rather than only to apply them.

## What ships

- **`base conv`** — convert between `raw`, `hex`, `b64`, `b32`, `bin` and `dec`.
  Strict about content, lenient about layout: a wrapped paste with newlines and
  a leading `0x` decodes fine, a non-hex character does not.
- **`xor`** — `apply` with a repeating key, `crack` a single-byte or
  repeating key, `crib` drag a known fragment. Candidates are ranked, and the
  recovered key is reduced to its smallest period.
- **`caesar`** and **`affine`** — apply, decrypt, and crack the whole keyspace.
  Keys are reported as they were applied, the way a challenge states them.
- **`rsa`** — `params`, `encrypt`, `decrypt` (from `d` or from the factors),
  `smalle`, `common-modulus` and `wiener`, over an arbitrary-precision integer
  written in this repository.
- **`analyze`** — length, printable share, index of coincidence and likely
  encodings for a blob you know nothing about.

Exit codes mean something: `0` produced a result, `1` ran correctly and found
nothing, `2` was asked wrong.

## What it deliberately does not do

No network access, so no factordb lookups. No hashing, no block-cipher or
padding-oracle tooling, no Vigenère, no substitution solver, no colour output
and no config file. These are absent on purpose; the four areas above are the
scope of this release.

## Known limitations

- **The arithmetic is not constant-time.** `bignum` is schoolbook: base 2^32
  limbs, schoolbook multiplication, Knuth long division. It is written for
  solving puzzles and for understanding the mathematics, and it leaks timing
  freely. Do not protect anything with this.
- **RSA here is textbook RSA.** No padding, no PKCS#1, no OAEP, no awareness of
  any of it.
- The differential tests for `bignum` need a 128-bit integer type, which MSVC
  does not have, so that half of the suite is enforced by the Linux CI job. The
  division tests, which check division by its own definition, run everywhere.
- `--min-printable` defaults to `0.9`, which will discard a genuine plaintext
  that is mostly binary. Pass `--min-printable 0` when hunting for one.

## Verification

`ctest` runs on Linux (GCC) and Windows (MSVC) with warnings as errors on every
push. Beyond the ordinary cases, the suite deliberately includes:

- a test runner that fails on purpose, so the harness cannot silently stop
  reporting failures;
- 5000-pair differential tests for `bignum` against a 128-bit built-in, and 500
  random division cases checked as `a == q·b + r` with `r < b`;
- a negative case for every guard — the inputs that must throw, and separately
  the attacks that must return **nothing** rather than a wrong answer: a
  non-cube for `smalle`, a safe key for `wiener`, a ciphertext pair that is not
  genuine for `common-modulus`;
- rank-1 assertions for every cracker, rather than "somewhere in the top ten".

Two bugs found by those tests during development, both of the same shape — a
confident wrong answer — are fixed here: the repeating-key XOR cracker preferred
over-fitted long keys on short ciphertexts, and Wiener's continued-fraction
recurrence had its seed values swapped so it never reached the real exponent.

MIT licensed.
