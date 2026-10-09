# CryptRift design

The short version, for someone about to change the code. The full reasoning,
including the alternatives that were rejected, is in
[the spec](superpowers/specs/2026-10-09-cryptrift-design.md).

## Shape

A static library of pure functions, plus a thin command-line adapter.

```
include/cryptrift/   public headers of the core library
src/core/            implementation: no I/O, no printing, no exit
src/cli/             argv parsing, dispatch, rendering
tests/               one test file per module, driven by CTest
```

Three targets: `cryptrift_core` (the library), `cryptrift_cli` (the command
layer, a library so the tests can call it directly), and `cryptrift` (the
binary). Plus `ct_tests` and `ct_selftest`.

## The one hard rule

**`src/core/` performs no I/O.** No `argv`, no `std::cin`, no `std::cout`, no
`exit`. Core functions take values and return values or throw. Everything the
user sees is produced in `src/cli/`.

This is not tidiness. It is what lets every attack be tested as a direct
function call, asserting on a structured result, instead of by running the
binary and grepping its output. Failures then say which function is wrong rather
than that some text did not appear.

The CLI is tested both ways: `parse_args` and the handlers are called directly,
and a small runner drives the real binary for the things that only exist in the
assembled program — exit codes, stream discipline, and binary-safe output.

## Dependency order

Modules depend downward only. Changing one never requires looking upward.

```
error
  ├── bytes ─── score ─── xor_tool
  │      │         └───── classical
  │      └──────── codec ─── analyze
  └── bignum ──── rsa
         └─────── codec   (for the dec format only)
```

`bignum` depends on `error` alone, deliberately: faster multiplication could be
dropped in without `rsa` noticing. `codec` reaches for `bignum` only to read and
write the `dec` format, rather than carrying a second decimal/binary conversion.

## Invalid input versus found nothing

Two situations that look similar and must never be conflated.

**Invalid input** — malformed hex, an affine multiplier sharing a factor with
26, a modulus of zero. The core throws `cryptrift::Error`, the CLI catches it at
the top level, writes `cryptrift: <message>` to stderr and exits **2**. Nothing
reaches stdout.

**Found nothing** — a brute force where no candidate cleared the filter, Wiener
against a key it cannot reach. This is not an exception; it is an empty result.
The CLI says so on stderr and exits **1**.

Everything else about this project follows from taking that distinction
seriously. A control that reports itself successful while having done nothing is
the failure mode here: a cracker that prints an empty table and exits 0, or an
attack that returns a key it never checked. So every attack verifies its own
result before returning it, and the test suite contains a negative case for
every guard — including a test runner that deliberately fails, to prove the
harness can still report a failure.

## Where the test effort goes

- **`bignum`** carries the heaviest burden, because a silent arithmetic error
  there would make every answer above it wrong in a way no eye would catch. Add,
  subtract and multiply are compared against a 128-bit built-in across 5000
  random pairs; division is checked by its own definition (`a == q·b + r` with
  `r < b`) over 500 random limb-length combinations, since no reference exists
  at that width.
- **Crackers** must put the right answer at **rank 1**, not merely in the top
  ten. "Somewhere in the list" would let the scoring rot unnoticed.
- **Attacks** need a test that they *refuse* a case they cannot solve. That test
  is the important one.
