# CryptRift

[![CI](https://github.com/mntoyg/CryptRift/actions/workflows/ci.yml/badge.svg)](https://github.com/mntoyg/CryptRift/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](https://en.cppreference.com/w/cpp/17)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](CMakeLists.txt)

A command-line C++ toolkit for common CTF crypto tasks — XOR, affine, RSA
helpers, base conversions — to speed up challenge solving and to strengthen
practical cryptography skills.

It does not just transform with a key you already have; it recovers the key.

> **Status: in development.** The command surface lands task by task; see
> [the plan](docs/superpowers/plans/2026-10-09-cryptrift.md) for what is built
> and what is next. This README is completed at the v0.1.0 release.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

No dependencies to install: the big-integer arithmetic behind the RSA helpers
is written in this repository, which is half the point of it.

## Design

The architecture, the module dependency order, and the rule that `src/core/`
performs no I/O are described in
[the design spec](docs/superpowers/specs/2026-10-09-cryptrift-design.md).

## Licence

MIT — see [LICENSE](LICENSE).
