# Contributing to CryptRift

## Build and test

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

CI builds with warnings as errors; reproduce that locally before opening a pull
request:

```bash
cmake -S . -B build -DCRYPTRIFT_WERROR=ON
```

Two tests always run. `unit` is the suite. `harness_selftest` fails on purpose
and is registered with `WILL_FAIL`, which proves the harness can still report a
failure; if it ever starts exiting 0, every other test in the suite has become
decorative.

## The two rules

**1. `src/core/` performs no I/O.** No `argv`, no `std::cin`, no `std::cout`, no
`exit`. Core functions take values and return values or throw. Everything the
user sees is produced in `src/cli/`. This is what lets every attack be tested as
a direct function call instead of by running the binary and grepping its output.

**2. An attack that found nothing says so.** Invalid input throws
`cryptrift::Error` and the CLI exits 2. An attack that ran correctly and found
nothing returns an empty result and the CLI exits 1. These are never conflated,
and a recovered key is verified before it is returned.

So a new attack ships with two tests: one proving it solves a case it should
solve, and one proving it **refuses** a case it cannot. The second test is the
important one. A cracker that reports success while holding garbage is worse
than no cracker at all, and it is the failure this project is organised to
prevent.

## Tests

Test-first. Write the failing test, run it, watch it fail for the right reason,
then implement. The harness lives in `tests/ct_test.hpp` and gives you
`CT_CHECK`, `CT_CHECK_EQ` and `CT_CHECK_THROWS`; add a `test_<module>.cpp`, a
`run_<module>_tests()` declaration in `tests/tests.hpp`, a call in
`tests/main.cpp`, and the file to `tests/CMakeLists.txt`.

For a brute-force attack, assert that the right answer comes back at **rank 1**,
not merely somewhere in the list. "In the top ten" lets the scoring rot without
any test noticing.
