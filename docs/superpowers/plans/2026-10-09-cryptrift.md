# CryptRift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `cryptrift`, a dependency-free C++17 command-line toolkit that recovers keys for common CTF crypto tasks — XOR, affine/Caesar, RSA helpers, base conversions — rather than only applying keys you already have.

**Architecture:** A `cryptrift_core` static library of pure functions (no I/O, no printing, no `exit`) plus a thin `cryptrift` CLI that parses argv, calls core, and renders. Tests link the core directly and assert on structured results; a small set of smoke tests run the real binary to pin exit codes. Modules depend downward only: `error` → `bytes`/`bignum` → `codec`/`score` → `xor_tool`/`classical`/`rsa` → `analyze` → CLI.

**Tech Stack:** C++17, CMake ≥ 3.14, CTest, an in-repo test header. No third-party libraries.

**Spec:** [docs/superpowers/specs/2026-10-09-cryptrift-design.md](../specs/2026-10-09-cryptrift-design.md)

## Global Constraints

- C++17. No external dependencies — not even on AlgoVault. No network access at runtime.
- `src/core/` never reads `argv`, never touches `std::cin`/`std::cout`/`std::cerr`, and never calls `exit`. It takes values and returns values or throws.
- Invalid input throws `cryptrift::Error`; an attack that found nothing returns an empty result. These are never conflated.
- Exit codes: `0` success, `1` ran correctly but found nothing, `2` usage or input error.
- Diagnostics go to stderr prefixed `cryptrift: `. stdout carries results only, so pipes stay clean.
- Formats: `raw|hex|b64|b32|bin|dec`, default `raw`. `dec` means one non-negative big-endian integer in decimal, and is only accepted from Task 14 onward.
- Defaults: `--top 10`, `--min-printable 0.9`.
- CI builds `ubuntu-latest` and `windows-latest` with `-Wall -Wextra -Werror` (`/W4 /WX` on MSVC) and runs `ctest --output-on-failure`.
- Every recovered key is verified before being returned.
- Repo: `github.com/mntoyg/CryptRift`, public, MIT. Code, comments, docs and commit messages in English.
- Targets: `cryptrift_core` (static), `cryptrift` (executable), `ct_tests` (test executable), `ct_selftest` (harness self-test).

**Two deliberate deviations from the spec**, both in service of its own no-I/O rule:

- Spec §4.2 gives `bytes` a `read_input(const InputSpec&)` that can read stdin. Switching a stream to binary mode is I/O, so `bytes` keeps only `read_stream`/`read_file` (Task 2) and source selection moves to the CLI as `load_input` (Task 4). No task defines `InputSpec`.
- Spec §4.3 has `codec` depending on `error` alone, but `Format::dec` is a big-integer conversion. Rather than duplicate that arithmetic, `codec` delegates `dec` to `bignum` (Task 14) and therefore depends on it. `dec` is rejected with exit 2 until Task 14 lands.

## Review Focus

Five things the spec implies but does not pin, ordered by how likely they are to bite a real user. Each line's test is assigned to the task that owns the code.

1. **A wrapped CTF blob.** Hex and base64 are routinely pasted with newlines, spaces or an `0x` prefix. Strict decoding would reject a perfectly ordinary paste, so ASCII whitespace is skipped and a leading `0x`/`0X` on hex is accepted. → Task 3.
2. **An empty key.** `xor apply --key ""` would take `index % key.size()` with size zero. It must be a usage `Error`, not a crash. → Task 6.
3. **Empty input.** Scoring zero bytes divides by zero and yields NaN, which then sorts unpredictably. `english_score({}) == 0.0` exactly, and a crack of empty input returns no candidates (exit 1). → Task 5.
4. **Binary output on Windows.** The spec sets stdin to binary mode but says nothing about stdout; in text mode a `0x0A` in recovered plaintext becomes `0x0D 0x0A` and `-q | base64 -d` silently corrupts. stdout is set to binary before any raw write. → Task 8.
5. **Bignum zero and one.** `divmod` by zero, `modpow` with modulus 1 or exponent 0, `sub` to exactly zero, and parsing `"0"` or `"0007"` all hit the normalization path where a stray empty-or-not-empty limb vector causes wrong answers rather than crashes. → Tasks 11–13.

---

## Task 1: Repo skeleton, test harness, error type

**Files:**
- Create: `CMakeLists.txt`, `.gitignore`, `.gitattributes`, `LICENSE`, `README.md`, `CONTRIBUTING.md`
- Create: `.github/workflows/ci.yml`
- Create: `include/cryptrift/error.hpp`
- Create: `tests/CMakeLists.txt`, `tests/ct_test.hpp`, `tests/tests.hpp`, `tests/main.cpp`, `tests/selftest.cpp`, `tests/test_error.cpp`

**Interfaces:**
- Consumes: nothing.
- Produces: `cryptrift::Error : std::runtime_error` (constructor takes `const std::string&`). Test macros `CT_CHECK(expr)`, `CT_CHECK_EQ(a, b)`, `CT_CHECK_THROWS(expr, ExcType)`, plus `int ct::failures()`. Each `tests/test_*.cpp` exposes one `void run_<module>_tests();` declared in `tests/tests.hpp` and called from `tests/main.cpp`, which returns non-zero when `ct::failures() > 0`.

- [ ] **Step 1: Write the failing tests**

`tests/test_error.cpp`:
```cpp
void run_error_tests() {
    CT_CHECK_THROWS(throw cryptrift::Error("bad hex"), cryptrift::Error);
    try { throw cryptrift::Error("bad hex"); }
    catch (const cryptrift::Error& e) { CT_CHECK_EQ(std::string(e.what()), std::string("bad hex")); }
    CT_CHECK(std::is_base_of<std::runtime_error, cryptrift::Error>::value);
}
```

`tests/selftest.cpp` is a separate `main` that runs one deliberately false check and returns `ct::failures() == 0 ? 0 : 1`. It proves the harness reports failures instead of passing silently — a test runner that cannot fail is the same bug shape as a cracker that reports success while holding garbage.

- [ ] **Step 2: Run to verify it fails**

Run: `cmake -S . -B build && cmake --build build`
Expected: FAIL — `cryptrift/error.hpp` not found.

- [ ] **Step 3: Implement the skeleton**

`include/cryptrift/error.hpp`: `namespace cryptrift { class Error : public std::runtime_error { public: explicit Error(const std::string& what); }; }`.

`CMakeLists.txt`: `cmake_minimum_required(VERSION 3.14)`, `project(CryptRift VERSION 0.1.0 LANGUAGES CXX)`, `HOMEPAGE_URL "https://github.com/mntoyg/CryptRift"`, C++17 required. An `add_library(cryptrift_core STATIC)` with `target_include_directories(... PUBLIC include)` and no sources yet (add an empty `src/core/version.cpp` exposing `cryptrift::version()` returning `"0.1.0"` so the target links). Option `CRYPTRIFT_WERROR` (default `OFF`) appends `-Wall -Wextra -Wshadow -Wpedantic -Werror`, or `/W4 /WX` under MSVC, to all three targets. `enable_testing()` and `add_subdirectory(tests)` only when top level.

`tests/CMakeLists.txt`: builds `ct_tests` from `main.cpp` + every `test_*.cpp`, links `cryptrift_core`, `add_test(NAME unit COMMAND ct_tests)`. Builds `ct_selftest` from `selftest.cpp`, `add_test(NAME harness_selftest COMMAND ct_selftest)` with `set_tests_properties(harness_selftest PROPERTIES WILL_FAIL TRUE)`.

`.gitattributes`: `* text=auto eol=lf` so clones outside Windows do not see a whole-file diff.

`.gitignore`: `build/`, `.vs/`, `.idea/`, `*.user`, `cmake-build-*/`.

`LICENSE`: MIT, copyright holder `mntoyg`, year 2026.

`README.md` at this stage: project title, the one-line purpose from the spec §1, CI and license badges, and a "status: in development" note. It is finished in Task 20.

`CONTRIBUTING.md`: how to configure, build and run `ctest`; the `src/core/` no-I/O rule; the requirement that a new attack ships with a test proving it refuses a case it cannot solve.

`.github/workflows/ci.yml`: `on: [push, pull_request]`, matrix `os: [ubuntu-latest, windows-latest]`, steps configure with `-DCRYPTRIFT_WERROR=ON`, build, then `ctest --test-dir build --output-on-failure`.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure`
Expected: PASS — both `unit` and `harness_selftest`. Confirm `harness_selftest` passes *because it failed*: temporarily flip its check to true and re-run, expecting that test to be reported as failed, then flip it back.

- [ ] **Step 5: Create the public repo and push**

```bash
gh repo create CryptRift --public --source=. --remote=origin \
  --description "A command-line C++ toolkit for common CTF crypto tasks (XOR, affine, RSA helpers, base conversions)"
git add -A && git commit -m "build: project skeleton, test harness and CI"
git push -u origin main
gh run watch
```
Expected: CI green on both runners before Task 2 starts.

---

## Task 2: `bytes` — the data type and input sources

**Files:**
- Create: `include/cryptrift/bytes.hpp`, `src/core/bytes.cpp`, `tests/test_bytes.cpp`
- Modify: `CMakeLists.txt` (add source), `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `cryptrift::Error`.
- Produces:
```cpp
using Bytes = std::vector<std::uint8_t>;
Bytes read_stream(std::istream& in);                 // binary-safe, no interpretation
Bytes read_file(const std::string& path);            // throws Error when unreadable
Bytes from_string(std::string_view s);
std::string to_string(const Bytes& b);
```

- [ ] **Step 1: Write the failing tests** in `tests/test_bytes.cpp`

```cpp
void run_bytes_tests() {
    std::istringstream in(std::string("a\0b", 3));
    CT_CHECK_EQ(read_stream(in), Bytes({'a', 0x00, 'b'}));      // NUL survives
    std::istringstream empty("");
    CT_CHECK_EQ(read_stream(empty), Bytes{});
    CT_CHECK_THROWS(read_file("no/such/file"), cryptrift::Error);
    CT_CHECK_EQ(to_string(from_string("hi")), std::string("hi"));
}
```

- [ ] **Step 2: Run to verify it fails** — `ctest --test-dir build -R unit`; expected FAIL to compile.

- [ ] **Step 3: Implement** the four functions in `src/core/bytes.cpp`. `read_stream` reads to EOF via `std::istreambuf_iterator`. `read_file` opens with `std::ios::binary` and throws `Error("cannot read <path>")` on failure. Reading *stdin* is the CLI's job (Task 4), because switching a stream to binary mode is I/O.

- [ ] **Step 4: Run to verify it passes** — `ctest --test-dir build --output-on-failure`; expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): bytes type and input readers"`

---

## Task 3: `codec` — hex, bin, raw, b64, b32

**Files:**
- Create: `include/cryptrift/codec.hpp`, `src/core/codec.cpp`, `tests/test_codec.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `Bytes`, `Error`.
- Produces:
```cpp
enum class Format { raw, hex, b64, b32, bin, dec };
std::optional<Format> format_from_name(std::string_view name);   // "hex" -> Format::hex
std::string format_name(Format f);
Bytes decode(Format f, std::string_view text);                   // throws Error
std::string encode(Format f, const Bytes& data);
```
`Format::dec` throws `Error("decimal format requires the bignum module")` until Task 14 replaces that branch.

- [ ] **Step 1: Write the failing tests** in `tests/test_codec.cpp`

```cpp
void run_codec_tests() {
    // RFC 4648 vectors
    CT_CHECK_EQ(encode(Format::b64, from_string("foobar")), std::string("Zm9vYmFy"));
    CT_CHECK_EQ(encode(Format::b64, from_string("fo")),     std::string("Zm8="));
    CT_CHECK_EQ(encode(Format::b32, from_string("foobar")), std::string("MZXW6YTBOI======"));
    CT_CHECK_EQ(decode(Format::b64, "Zm9vYmFy"), from_string("foobar"));
    CT_CHECK_EQ(decode(Format::b32, "MZXW6YTBOI======"), from_string("foobar"));

    CT_CHECK_EQ(encode(Format::hex, Bytes({0xDE, 0xAD})), std::string("dead"));
    CT_CHECK_EQ(decode(Format::hex, "DEAD"), Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(encode(Format::bin, Bytes({0x05})), std::string("00000101"));

    // Review Focus 1: a wrapped CTF blob must decode, not error
    CT_CHECK_EQ(decode(Format::hex, "de ad\n be\tef"), Bytes({0xDE, 0xAD, 0xBE, 0xEF}));
    CT_CHECK_EQ(decode(Format::hex, "0xdead"), Bytes({0xDE, 0xAD}));
    CT_CHECK_EQ(decode(Format::b64, "Zm9v\nYmFy"), from_string("foobar"));

    // strict where it matters
    CT_CHECK_THROWS(decode(Format::hex, "abc"),  cryptrift::Error);   // odd length
    CT_CHECK_THROWS(decode(Format::hex, "zz"),   cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::b64, "Zm9!"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::b64, "Zm9"),  cryptrift::Error);   // bad padding
    CT_CHECK_EQ(decode(Format::raw, "any\0thing"), from_string("any\0thing"));
    CT_CHECK(!format_from_name("rot13").has_value());

    for (const auto f : {Format::hex, Format::b64, Format::b32, Format::bin, Format::raw}) {
        const Bytes blob = /* 0..255 */;
        CT_CHECK_EQ(decode(f, encode(f, blob)), blob);               // round trip
    }
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/codec.cpp`. Share one whitespace-skipping pass across hex, b64, b32 and bin so the rule lives in a single place. `encode(Format::hex, ...)` emits lowercase and no `0x`; `decode` accepts either case and one optional leading `0x`. Base32 encodes with `=` padding to a multiple of 8 characters.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): strict codec for hex, bin, base64 and base32"`

---

## Task 4: CLI skeleton — dispatch, `base conv`, help, version

**Files:**
- Create: `src/cli/main.cpp`, `src/cli/args.hpp`, `src/cli/args.cpp`, `src/cli/render.hpp`, `src/cli/render.cpp`, `src/cli/binary_io.hpp`, `src/cli/binary_io.cpp`, `src/cli/cmd_base.cpp`, `src/cli/commands.hpp`
- Create: `tests/cli_runner.hpp`, `tests/cli_runner.cpp`, `tests/test_args.cpp`, `tests/test_cli.cpp`
- Modify: `CMakeLists.txt` (add the `cryptrift` executable), `tests/CMakeLists.txt` (pass `CRYPTRIFT_BIN` as a compile definition), `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `codec`, `bytes`, `Error`.
- Produces:
```cpp
// src/cli/args.hpp
constexpr int kOk = 0, kNoResult = 1, kUsage = 2;
struct Args {                       // parsed, not yet validated per command
    std::string group, command;     // e.g. "base", "conv"
    std::vector<std::string> positional;
    std::map<std::string, std::string> flags;   // "--top" -> "5"; valueless flags map to ""
};
Args parse_args(const std::vector<std::string>& argv_tail);   // throws Error on malformed flags
std::string require(const Args&, const std::string& flag);    // throws Error when absent
Format require_format(const Args&, const std::string& flag, Format fallback);
Bytes load_input(const Args&, Format in_format, std::istream& stdin_stream);
int run(const std::vector<std::string>& argv_tail, std::istream& in, std::ostream& out, std::ostream& err);
// src/cli/binary_io.hpp
void set_stdio_binary();            // _setmode on _WIN32, no-op elsewhere
// tests/cli_runner.hpp
struct Run { int exit_code; std::string out; std::string err; };
Run run_cli(const std::string& args, const std::string& stdin_data = "");
```
`run` takes streams so the whole CLI is testable in-process; `main` wires `std::cin`/`cout`/`cerr`, calls `set_stdio_binary()` first, catches `Error` → `err << "cryptrift: " << e.what()` and returns `kUsage`.

- [ ] **Step 1: Write the failing tests**

`tests/test_args.cpp`:
```cpp
void run_args_tests() {
    const Args a = parse_args({"xor", "crack", "--top", "5", "-q", "deadbeef"});
    CT_CHECK_EQ(a.group, std::string("xor"));
    CT_CHECK_EQ(a.command, std::string("crack"));
    CT_CHECK_EQ(a.flags.at("--top"), std::string("5"));
    CT_CHECK_EQ(a.flags.at("-q"), std::string(""));
    CT_CHECK_EQ(a.positional, std::vector<std::string>{"deadbeef"});
    CT_CHECK_THROWS(parse_args({"base", "conv", "--in-format"}), cryptrift::Error);  // flag wants a value
    CT_CHECK_THROWS(require(a, "--key"), cryptrift::Error);
}
```

`tests/test_cli.cpp` (through the real binary, to pin exit codes and stream discipline):
```cpp
void run_cli_tests() {
    Run r = run_cli("base conv --in-format hex --out-format b64 4d7a");
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK_EQ(r.out, std::string("TXo="));
    CT_CHECK_EQ(r.err, std::string(""));                       // stdout stays clean

    r = run_cli("base conv --in-format hex --out-format raw", "4d7a");   // input from stdin
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK_EQ(r.out, std::string("Mz"));

    r = run_cli("base conv --in-format hex --out-format b64 zz");
    CT_CHECK_EQ(r.exit_code, 2);
    CT_CHECK(r.err.rfind("cryptrift: ", 0) == 0);
    CT_CHECK_EQ(r.out, std::string(""));                       // no partial output

    CT_CHECK_EQ(run_cli("nonsense thing").exit_code, 2);
    CT_CHECK_EQ(run_cli("--version").exit_code, 0);
    CT_CHECK(run_cli("--version").out.find("0.1.0") != std::string::npos);
    CT_CHECK_EQ(run_cli("help").exit_code, 0);
    CT_CHECK_EQ(run_cli("base conv --in-format dec --out-format hex 42").exit_code, 2);  // dec not yet
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement**

`run` dispatches on `group` then `command` through a table in `src/cli/commands.hpp` so later tasks add a group by adding one entry. `cmd_base.cpp` implements `conv`: decode input in `--in-format`, encode to `--out-format`, write to `out`. An unknown group, unknown command, unknown format name or absent required flag throws `Error`.

`load_input` resolves the spec's three sources in order: a positional value, else `--in FILE`, else the stdin stream (also used when the positional is exactly `-`).

`render.cpp` for now holds only `void write_raw(std::ostream&, const Bytes&)`, writing with `out.write(...)` and no added newline.

`cli_runner.cpp` runs `CRYPTRIFT_BIN` with stdout and stderr redirected to files in the directory CTest runs in, feeding `stdin_data` through a third temp file, via `std::system`; it normalizes the return value with `WEXITSTATUS` where available so exit codes compare equal on both platforms.

- [ ] **Step 4: Run to verify it passes** — `cmake --build build && ctest --test-dir build --output-on-failure`; expected PASS.

- [ ] **Step 5: Commit and push** — `git add -A && git commit -m "feat(cli): dispatch, base conv, help and exit codes"`, then `git push && gh run watch` to confirm CI is still green on Windows, where the binary-mode and `std::system` paths differ.

---

## Task 5: `score` — English-likeness

**Files:**
- Create: `include/cryptrift/score.hpp`, `src/core/score.cpp`, `tests/test_score.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `Bytes`.
- Produces:
```cpp
double printable_ratio(const Bytes& data);        // 0.0 for empty
double english_score(const Bytes& data);          // higher is better; exactly 0.0 for empty
```

- [ ] **Step 1: Write the failing tests** in `tests/test_score.cpp`

```cpp
void run_score_tests() {
    const Bytes english = from_string("the quick brown fox jumps over the lazy dog");
    const Bytes noise   = Bytes({0x00, 0xFF, 0x01, 0xFE, 0x7F, 0x80, 0x02});
    CT_CHECK(english_score(english) > english_score(noise));
    CT_CHECK(english_score(english) > english_score(from_string("zzzzzzzzzzzzzzzzzzzz")));

    // Review Focus 3: empty input must be a defined score, never NaN
    CT_CHECK_EQ(english_score(Bytes{}), 0.0);
    CT_CHECK_EQ(printable_ratio(Bytes{}), 0.0);
    CT_CHECK(english_score(Bytes{}) == english_score(Bytes{}));   // not NaN

    CT_CHECK_EQ(printable_ratio(from_string("abc")), 1.0);
    CT_CHECK(printable_ratio(Bytes({'a', 0x00})) < 1.0);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/score.cpp`. `printable_ratio` counts bytes in `0x20..0x7E` plus `\t\n\r` over the total, returning `0.0` when the input is empty. `english_score` combines, for non-empty input: the printable ratio weighted heavily, the negated chi-squared distance between observed A–Z frequencies (case-folded, non-letters excluded) and a table of English letter frequencies stored as a `constexpr` array, and a small bonus for occurrences of the most common English bigrams (`th`, `he`, `in`, `er`, `an`). Guard every division by a zero denominator — a text of only digits has no letters to compare.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): English-likeness scoring"`

---

## Task 6: `xor_tool` — apply and single-byte crack

**Files:**
- Create: `include/cryptrift/xor_tool.hpp`, `src/core/xor_tool.cpp`, `tests/test_xor.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `Bytes`, `score`, `Error`.
- Produces:
```cpp
struct Candidate { Bytes key; Bytes plaintext; double score; };
Bytes apply_repeating(const Bytes& data, const Bytes& key);     // throws Error when key is empty
std::vector<Candidate> crack_single_byte(const Bytes& data, double min_printable, std::size_t limit);
```
`crack_single_byte` tries all 256 keys, keeps those whose `printable_ratio` ≥ `min_printable`, sorts by `score` descending, and truncates to `limit` (`0` means no limit).

- [ ] **Step 1: Write the failing tests** in `tests/test_xor.cpp`

```cpp
void run_xor_tests() {
    CT_CHECK_EQ(apply_repeating(from_string("abc"), Bytes({0x00})), from_string("abc"));
    const Bytes data = from_string("hello world"), key = from_string("KEY");
    CT_CHECK_EQ(apply_repeating(apply_repeating(data, key), key), data);   // involution

    // Review Focus 2: an empty key must not reach index % 0
    CT_CHECK_THROWS(apply_repeating(data, Bytes{}), cryptrift::Error);

    const Bytes plain  = from_string("The flag is flag{xor_is_not_encryption}");
    const Bytes cipher = apply_repeating(plain, Bytes({0x5A}));
    const auto hits = crack_single_byte(cipher, 0.9, 10);
    CT_CHECK(!hits.empty());
    CT_CHECK_EQ(hits.front().plaintext, plain);          // rank 1, not "somewhere in the top 10"
    CT_CHECK_EQ(hits.front().key, Bytes({0x5A}));
    for (std::size_t i = 1; i < hits.size(); ++i) CT_CHECK(hits[i - 1].score >= hits[i].score);

    // Review Focus 3: no candidates rather than a NaN-sorted list
    CT_CHECK(crack_single_byte(Bytes{}, 0.9, 10).empty());
    CT_CHECK(crack_single_byte(Bytes({0x00, 0x01, 0x02}), 0.99, 10).empty());
    CT_CHECK_EQ(crack_single_byte(cipher, 0.0, 0).size(), 256u);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/xor_tool.cpp`. `apply_repeating` throws `Error("xor key must not be empty")` before the loop.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): XOR apply and single-byte crack"`

---

## Task 7: `xor_tool` — repeating-key crack and crib drag

**Files:**
- Modify: `include/cryptrift/xor_tool.hpp`, `src/core/xor_tool.cpp`, `tests/test_xor.cpp`

**Interfaces:**
- Consumes: Task 6's `Candidate`, `crack_single_byte`.
- Produces:
```cpp
struct KeyLenRange { std::size_t min = 2; std::size_t max = 40; };
std::vector<std::size_t> guess_key_lengths(const Bytes& data, KeyLenRange range, std::size_t top);
std::vector<Candidate> crack_repeating(const Bytes& data, KeyLenRange range,
                                       double min_printable, std::size_t limit);
struct CribHit { std::size_t offset; Bytes key_fragment; };
std::vector<CribHit> crib_drag(const Bytes& cipher, const Bytes& crib);   // throws Error on empty crib
```

- [ ] **Step 1: Write the failing tests** (append to `tests/test_xor.cpp`)

```cpp
void run_xor_repeating_tests() {
    const Bytes plain = from_string(/* ~400 chars of English prose */);
    const Bytes key   = from_string("RIFT");
    const Bytes cipher = apply_repeating(plain, key);

    const auto lengths = guess_key_lengths(cipher, KeyLenRange{2, 20}, 3);
    CT_CHECK(std::find(lengths.begin(), lengths.end(), 4u) != lengths.end());

    const auto hits = crack_repeating(cipher, KeyLenRange{2, 20}, 0.9, 5);
    CT_CHECK(!hits.empty());
    CT_CHECK_EQ(hits.front().key, key);
    CT_CHECK_EQ(hits.front().plaintext, plain);

    CT_CHECK(crack_repeating(Bytes{}, KeyLenRange{2, 20}, 0.9, 5).empty());
    CT_CHECK(crack_repeating(from_string("ab"), KeyLenRange{8, 20}, 0.9, 5).empty());  // shorter than min

    const auto drag = crib_drag(cipher, from_string("the"));
    CT_CHECK_EQ(drag.size(), cipher.size() - 2);
    CT_CHECK_EQ(drag.front().offset, 0u);
    CT_CHECK_EQ(drag.front().key_fragment.size(), 3u);
    CT_CHECK_THROWS(crib_drag(cipher, Bytes{}), cryptrift::Error);
    CT_CHECK(crib_drag(from_string("ab"), from_string("abcd")).empty());   // crib longer than data
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** `guess_key_lengths` scores each candidate length by the mean normalized Hamming distance between consecutive blocks of that length — lower is better — and returns the best `top` lengths; lengths exceeding `data.size() / 2` are skipped. `crack_repeating` transposes the data into one column per key byte, runs `crack_single_byte(column, 0.0, 1)` on each, reassembles the key, then filters the reassembled plaintext by `min_printable` and ranks by `english_score`. `crib_drag` XORs the crib against the cipher at every offset where it fits.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): repeating-key XOR crack and crib drag"`

---

## Task 8: CLI `xor` group and the candidate renderer

**Files:**
- Create: `src/cli/cmd_xor.cpp`
- Modify: `src/cli/render.hpp`, `src/cli/render.cpp`, `src/cli/commands.hpp`, `CMakeLists.txt`, `tests/test_cli.cpp`

**Interfaces:**
- Consumes: `xor_tool`, `load_input`, `require`, `write_raw`.
- Produces:
```cpp
void render_candidates(std::ostream& out, const std::vector<Candidate>& hits, std::size_t top);
std::size_t flag_top(const Args&);            // --top, default 10
double flag_min_printable(const Args&);       // --min-printable, default 0.9
bool flag_quiet(const Args&);                 // -q / --quiet
```
Commands: `xor apply` (`--key` xor `--key-hex`), `xor crack`, `xor crib --crib`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.cpp`)

```cpp
void run_cli_xor_tests() {
    // apply: hex in, hex out, round trip through the binary
    Run r = run_cli("xor apply --key-hex 5a --in-format raw --out-format hex abc");
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK_EQ(r.out, std::string("393b38"));

    // Review Focus 2: both keys, or neither, is a usage error
    CT_CHECK_EQ(run_cli("xor apply --key K --key-hex 4b abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor apply abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("xor apply --key \"\" abc").exit_code, 2);

    // crack: human table by default, raw best answer with -q
    const std::string cipher_hex = /* "flag{xor}" xored with 0x5a, as hex */;
    r = run_cli("xor crack --in-format hex " + cipher_hex);
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK(r.out.find("flag{xor}") != std::string::npos);
    CT_CHECK(r.out.find("5a") != std::string::npos);          // the key is shown
    r = run_cli("xor crack -q --in-format hex " + cipher_hex);
    CT_CHECK_EQ(r.out, std::string("flag{xor}"));             // bytes only, no table, no newline

    // Review Focus 4: a 0x0A in the plaintext must not become 0x0D 0x0A
    const std::string nl_hex = /* "a\nb" xored with 0x11, as hex */;
    r = run_cli("xor crack -q --min-printable 0 --in-format hex " + nl_hex);
    CT_CHECK(r.out.find('\r') == std::string::npos);

    // found nothing: exit 1, message on stderr, nothing on stdout
    r = run_cli("xor crack --min-printable 1.0 --in-format hex 00010203fcfdfe");
    CT_CHECK_EQ(r.exit_code, 1);
    CT_CHECK_EQ(r.out, std::string(""));
    CT_CHECK(r.err.find("no candidate found") != std::string::npos);

    CT_CHECK_EQ(run_cli("xor crib --crib flag{ --in-format hex " + cipher_hex).exit_code, 0);
    CT_CHECK_EQ(run_cli("xor crack --top notanumber abc").exit_code, 2);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** `render_candidates` prints a header row and then rank, key as hex, score to two decimals, and a preview of the first 48 plaintext bytes with non-printables shown as `.`. The `-q` path calls `write_raw` with `hits.front().plaintext` and prints nothing else. An empty result writes `cryptrift: no candidate found` to `err` and returns `kNoResult`. `flag_top`/`flag_min_printable` throw `Error` on a value that does not parse or falls outside `[0, 1]` for the ratio. Confirm `set_stdio_binary()` runs in `main` before any write, since Review Focus 4 depends on it.

- [ ] **Step 4: Run to verify it passes** — expected PASS on both platforms.

- [ ] **Step 5: Commit and push** — `git commit -m "feat(cli): xor apply, crack and crib with ranked output"`, then `gh run watch`.

---

## Task 9: `classical` — Caesar and affine

**Files:**
- Create: `include/cryptrift/classical.hpp`, `src/core/classical.cpp`, `tests/test_classical.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `Bytes`, `score`, `Error`.
- Produces:
```cpp
Bytes affine_encrypt(const Bytes& data, int a, int b);   // throws Error when gcd(a, 26) != 1
Bytes affine_decrypt(const Bytes& data, int a, int b);
Bytes caesar(const Bytes& data, int shift);              // affine_encrypt(data, 1, shift)
struct ClassicalCandidate { int a; int b; Bytes plaintext; double score; };
std::vector<ClassicalCandidate> crack_caesar(const Bytes&, double min_printable, std::size_t limit);
std::vector<ClassicalCandidate> crack_affine(const Bytes&, double min_printable, std::size_t limit);
```

- [ ] **Step 1: Write the failing tests** in `tests/test_classical.cpp`

```cpp
void run_classical_tests() {
    CT_CHECK_EQ(caesar(from_string("attack at dawn"), 3), from_string("dwwdfn dw gdzq"));
    CT_CHECK_EQ(caesar(from_string("Hello, World!"), 13), from_string("Uryyb, Jbeyq!"));
    CT_CHECK_EQ(caesar(caesar(from_string("abc"), 5), -5), from_string("abc"));
    CT_CHECK_EQ(caesar(from_string("a\xC3\xA9 1"), 1), from_string("b\xC3\xA9 1"));  // non-letters pass through

    CT_CHECK_EQ(affine_decrypt(affine_encrypt(from_string("the eagle has landed"), 5, 8), 5, 8),
                from_string("the eagle has landed"));
    CT_CHECK_THROWS(affine_encrypt(from_string("abc"), 13, 0), cryptrift::Error);   // gcd(13,26)=13
    CT_CHECK_THROWS(affine_encrypt(from_string("abc"), 0, 0),  cryptrift::Error);

    const Bytes plain = from_string("the flag for this challenge is a classical cipher");
    const auto caesar_hits = crack_caesar(caesar(plain, 7), 0.9, 5);
    CT_CHECK_EQ(caesar_hits.front().plaintext, plain);          // rank 1
    CT_CHECK_EQ(caesar_hits.front().b, 7);
    const auto affine_hits = crack_affine(affine_encrypt(plain, 11, 4), 0.9, 5);
    CT_CHECK_EQ(affine_hits.front().plaintext, plain);
    CT_CHECK_EQ(affine_hits.front().a, 11);
    CT_CHECK_EQ(affine_hits.front().b, 4);
    CT_CHECK_EQ(crack_affine(plain, 0.0, 0).size(), 12u * 26u);  // 12 invertible a values
    CT_CHECK(crack_caesar(Bytes{}, 0.9, 5).empty());
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/classical.cpp`. Preserve case, leave every byte that is not A–Z or a–z untouched, and normalize a negative or ≥ 26 shift into range. `crack_affine` iterates only the twelve `a` coprime with 26 and all 26 `b`.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): Caesar and affine ciphers with full-keyspace crack"`

---

## Task 10: CLI `caesar` and `affine` groups

**Files:**
- Create: `src/cli/cmd_classical.cpp`
- Modify: `src/cli/render.hpp`, `src/cli/render.cpp`, `src/cli/commands.hpp`, `CMakeLists.txt`, `tests/test_cli.cpp`

**Interfaces:**
- Consumes: `classical`, the Task 8 flag helpers.
- Produces: `void render_classical(std::ostream&, const std::vector<ClassicalCandidate>&, std::size_t top);`
  Commands: `caesar apply --shift N`, `caesar crack`, `affine apply --a A --b B`, `affine decrypt --a A --b B`, `affine crack`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.cpp`)

```cpp
void run_cli_classical_tests() {
    Run r = run_cli("caesar apply --shift 3 \"attack at dawn\"");
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK_EQ(r.out, std::string("dwwdfn dw gdzq"));
    CT_CHECK_EQ(run_cli("caesar crack -q \"dwwdfn dw gdzq\"").out, std::string("attack at dawn"));
    r = run_cli("affine crack \"Wklv lv d whvw phvvdjh iru wkh fudfnhu\"");
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK(r.out.find("a=1") != std::string::npos);     // the key is reported, not just the text
    CT_CHECK_EQ(run_cli("affine apply --a 13 --b 0 abc").exit_code, 2);
    CT_CHECK_EQ(run_cli("affine apply --b 3 abc").exit_code, 2);          // --a missing
    CT_CHECK_EQ(run_cli("caesar apply --shift xyz abc").exit_code, 2);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL.

- [ ] **Step 3: Implement.** `render_classical` shows rank, `a=`/`b=`, score and preview; `-q` writes the best plaintext raw. An empty result is `kNoResult`, as in Task 8.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(cli): caesar and affine groups"`

---

## Task 11: `bignum` — representation and additive arithmetic

**Files:**
- Create: `include/cryptrift/bignum.hpp`, `src/core/bignum.cpp`, `tests/test_bignum.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `Error`.
- Produces:
```cpp
class Bignum {
public:
    Bignum();                                    // zero
    explicit Bignum(std::uint64_t v);
    static Bignum from_hex(std::string_view s);  // throws Error; accepts optional 0x and whitespace
    std::string to_hex() const;                  // lowercase, no leading zeros, "0" for zero
    bool is_zero() const;
    std::size_t bit_length() const;              // 0 for zero
    static Bignum from_bytes_be(const std::vector<std::uint8_t>& b);
    std::vector<std::uint8_t> to_bytes_be() const;
};
int compare(const Bignum& a, const Bignum& b);                  // -1, 0, 1
Bignum add(const Bignum&, const Bignum&);
Bignum sub(const Bignum&, const Bignum&);                       // throws Error when b > a
Bignum mul(const Bignum&, const Bignum&);
Bignum shl(const Bignum&, std::size_t bits);
Bignum shr(const Bignum&, std::size_t bits);
```
Internally `std::vector<std::uint32_t>` limbs, little-endian, **always normalized so zero is an empty vector**. Every operation ends by trimming leading zero limbs; Review Focus 5 lives here.

- [ ] **Step 1: Write the failing tests** in `tests/test_bignum.cpp`

```cpp
void run_bignum_arith_tests() {
    CT_CHECK(Bignum().is_zero());
    CT_CHECK_EQ(Bignum().to_hex(), std::string("0"));
    CT_CHECK_EQ(Bignum(0).bit_length(), 0u);
    CT_CHECK_EQ(Bignum::from_hex("0007").to_hex(), std::string("7"));     // leading zeros normalized
    CT_CHECK_EQ(Bignum::from_hex("0x00").to_hex(), std::string("0"));
    CT_CHECK(Bignum::from_hex("00").is_zero());
    CT_CHECK_THROWS(Bignum::from_hex("12g4"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_hex(""),     cryptrift::Error);
    CT_CHECK_EQ(Bignum(0xFFFFFFFFFFFFFFFFull).to_hex(), std::string("ffffffffffffffff"));

    CT_CHECK(sub(Bignum(5), Bignum(5)).is_zero());                        // exact zero stays normalized
    CT_CHECK_THROWS(sub(Bignum(1), Bignum(2)), cryptrift::Error);
    CT_CHECK_EQ(compare(Bignum(0), Bignum()), 0);
    CT_CHECK(mul(Bignum(123456789), Bignum(0)).is_zero());

    // differential test against __int128, fixed seed, carry and borrow edges included
    std::mt19937_64 rng(20261009);
    for (int i = 0; i < 5000; ++i) {
        const std::uint64_t x = rng(), y = rng();
        CT_CHECK_EQ(add(Bignum(x), Bignum(y)).to_hex(), hex_of(static_cast<__uint128_t>(x) + y));
        CT_CHECK_EQ(mul(Bignum(x), Bignum(y)).to_hex(), hex_of(static_cast<__uint128_t>(x) * y));
        if (x >= y) CT_CHECK_EQ(sub(Bignum(x), Bignum(y)).to_hex(), hex_of(static_cast<__uint128_t>(x) - y));
    }
    for (const std::uint64_t edge : {0ull, 1ull, 0xFFFFFFFFull, 0x100000000ull, 0xFFFFFFFFFFFFFFFFull})
        CT_CHECK_EQ(add(Bignum(edge), Bignum(1)).to_hex(), hex_of(static_cast<__uint128_t>(edge) + 1));

    CT_CHECK_EQ(shl(Bignum(1), 64).to_hex(), std::string("10000000000000000"));
    CT_CHECK(shr(Bignum(1), 1).is_zero());
    CT_CHECK_EQ(shr(shl(Bignum(0xABCD), 100), 100).to_hex(), std::string("abcd"));
    CT_CHECK_EQ(Bignum::from_bytes_be({0x01, 0x00}).to_hex(), std::string("100"));
    CT_CHECK_EQ(Bignum::from_hex("100").to_bytes_be(), std::vector<std::uint8_t>({0x01, 0x00}));
    CT_CHECK(Bignum().to_bytes_be().empty());
}
```
`hex_of(__uint128_t)` is a local helper in the test file. MSVC has no `__int128`; guard the differential loop with `#if defined(__SIZEOF_INT128__)` and note in a comment that Linux CI is what enforces it.

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/bignum.cpp`. Schoolbook multiply accumulating into `std::uint64_t`. One private `trim()` called at the end of every operation that can shrink the result.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): bignum representation, add, sub, mul and shifts"`

---

## Task 12: `bignum` — divmod and decimal I/O

**Files:**
- Modify: `include/cryptrift/bignum.hpp`, `src/core/bignum.cpp`, `tests/test_bignum.cpp`

**Interfaces:**
- Consumes: Task 11's operations.
- Produces:
```cpp
struct DivResult { Bignum quot; Bignum rem; };
DivResult divmod(const Bignum& a, const Bignum& b);    // throws Error when b is zero
Bignum mod(const Bignum& a, const Bignum& m);
static Bignum Bignum::from_dec(std::string_view s);    // throws Error on non-digits or empty
std::string Bignum::to_dec() const;                    // "0" for zero
```

- [ ] **Step 1: Write the failing tests** (append to `tests/test_bignum.cpp`)

```cpp
void run_bignum_div_tests() {
    // Review Focus 5
    CT_CHECK_THROWS(divmod(Bignum(1), Bignum(0)), cryptrift::Error);
    CT_CHECK_THROWS(divmod(Bignum(0), Bignum(0)), cryptrift::Error);
    DivResult d = divmod(Bignum(0), Bignum(7));
    CT_CHECK(d.quot.is_zero() && d.rem.is_zero());
    d = divmod(Bignum(7), Bignum(9));                   // divisor longer than dividend
    CT_CHECK(d.quot.is_zero());
    CT_CHECK_EQ(d.rem.to_dec(), std::string("7"));
    d = divmod(Bignum(42), Bignum(42));
    CT_CHECK_EQ(d.quot.to_dec(), std::string("1"));
    CT_CHECK(d.rem.is_zero());
    CT_CHECK_EQ(divmod(Bignum(100), Bignum(1)).quot.to_dec(), std::string("100"));

    std::mt19937_64 rng(20261010);
    for (int i = 0; i < 5000; ++i) {
        const std::uint64_t x = rng(), y = (rng() | 1u);
        const DivResult r = divmod(Bignum(x), Bignum(y));
        CT_CHECK_EQ(r.quot.to_dec(), std::to_string(x / y));
        CT_CHECK_EQ(r.rem.to_dec(),  std::to_string(x % y));
    }
    // multi-limb case, verified by reconstruction: a == q*b + r with r < b
    const Bignum a = Bignum::from_hex("fedcba9876543210fedcba9876543210f1f2f3f4");
    const Bignum b = Bignum::from_hex("123456789abcdef0");
    const DivResult r = divmod(a, b);
    CT_CHECK_EQ(add(mul(r.quot, b), r.rem).to_hex(), a.to_hex());
    CT_CHECK(compare(r.rem, b) < 0);

    CT_CHECK_EQ(Bignum::from_dec("0").to_hex(), std::string("0"));
    CT_CHECK_EQ(Bignum::from_dec("0009").to_dec(), std::string("9"));
    CT_CHECK_EQ(Bignum::from_dec("340282366920938463463374607431768211456").to_hex(),
                std::string("100000000000000000000000000000000"));
    CT_CHECK_EQ(Bignum::from_hex("100000000000000000000000000000000").to_dec(),
                std::string("340282366920938463463374607431768211456"));
    CT_CHECK_THROWS(Bignum::from_dec("12a4"), cryptrift::Error);
    CT_CHECK_THROWS(Bignum::from_dec(""),     cryptrift::Error);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** Knuth-style schoolbook long division on 32-bit limbs with a 64-bit trial quotient and a correction loop, after an early return when the divisor exceeds the dividend. `from_dec` multiplies by 10 and adds each digit; `to_dec` repeatedly divides by 10^9 and formats the remainders.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): bignum divmod and decimal conversion"`

---

## Task 13: `bignum` — modular arithmetic and integer root

**Files:**
- Modify: `include/cryptrift/bignum.hpp`, `src/core/bignum.cpp`, `tests/test_bignum.cpp`

**Interfaces:**
- Consumes: Tasks 11–12.
- Produces:
```cpp
Bignum gcd(const Bignum& a, const Bignum& b);
Bignum modpow(const Bignum& base, const Bignum& exp, const Bignum& m);  // throws Error when m is zero
Bignum modinv(const Bignum& a, const Bignum& m);                        // throws Error when gcd(a,m) != 1
struct RootResult { Bignum root; bool exact; };
RootResult iroot(const Bignum& n, std::uint32_t k);                     // throws Error when k == 0
```

- [ ] **Step 1: Write the failing tests** (append to `tests/test_bignum.cpp`)

```cpp
void run_bignum_mod_tests() {
    CT_CHECK_EQ(gcd(Bignum(48), Bignum(18)).to_dec(), std::string("6"));
    CT_CHECK_EQ(gcd(Bignum(17), Bignum(0)).to_dec(),  std::string("17"));
    CT_CHECK_EQ(gcd(Bignum(0), Bignum(0)).to_dec(),   std::string("0"));

    // Review Focus 5
    CT_CHECK_THROWS(modpow(Bignum(2), Bignum(3), Bignum(0)), cryptrift::Error);
    CT_CHECK(modpow(Bignum(2), Bignum(10), Bignum(1)).is_zero());        // mod 1 is always 0
    CT_CHECK_EQ(modpow(Bignum(2), Bignum(0), Bignum(7)).to_dec(), std::string("1"));
    CT_CHECK(modpow(Bignum(0), Bignum(5), Bignum(7)).is_zero());
    CT_CHECK_EQ(modpow(Bignum(4), Bignum(13), Bignum(497)).to_dec(), std::string("445"));

    CT_CHECK_EQ(modinv(Bignum(3), Bignum(11)).to_dec(), std::string("4"));
    CT_CHECK_EQ(modinv(Bignum(17), Bignum(3120)).to_dec(), std::string("2753"));
    CT_CHECK_THROWS(modinv(Bignum(4), Bignum(8)),  cryptrift::Error);    // gcd 4
    CT_CHECK_THROWS(modinv(Bignum(0), Bignum(11)), cryptrift::Error);

    RootResult r = iroot(Bignum(1000), 3);
    CT_CHECK_EQ(r.root.to_dec(), std::string("10"));
    CT_CHECK(r.exact);
    r = iroot(Bignum(999), 3);
    CT_CHECK_EQ(r.root.to_dec(), std::string("9"));                      // floor
    CT_CHECK(!r.exact);
    r = iroot(Bignum::from_dec("1000000000000000000000000000"), 3);
    CT_CHECK_EQ(r.root.to_dec(), std::string("1000000000"));
    CT_CHECK(r.exact);
    CT_CHECK(iroot(Bignum(0), 3).root.is_zero());
    CT_CHECK_EQ(iroot(Bignum(5), 1).root.to_dec(), std::string("5"));
    CT_CHECK_THROWS(iroot(Bignum(5), 0), cryptrift::Error);

    // modpow at realistic size: Fermat's little theorem on a 256-bit prime
    const Bignum p = Bignum::from_dec(/* a known 256-bit prime */);
    CT_CHECK_EQ(modpow(Bignum(2), sub(p, Bignum(1)), p).to_dec(), std::string("1"));
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** `modpow` is square-and-multiply over the exponent's bits, reducing with `mod` at each step. `modinv` is the iterative extended Euclid over `Bignum` with sign tracking, throwing when the final gcd is not 1. `iroot` uses Newton iteration from an initial guess derived from `bit_length() / k`, then checks exactness by raising the result back to the `k`-th power. Bound the iteration and assert convergence rather than looping forever on a bad guess.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): bignum gcd, modpow, modinv and integer k-th root"`

---

## Task 14: `codec` — the `dec` format

**Files:**
- Modify: `src/core/codec.cpp`, `tests/test_codec.cpp`, `CMakeLists.txt` (codec now links against bignum within the same target)

**Interfaces:**
- Consumes: `Bignum::from_dec`, `to_dec`, `from_bytes_be`, `to_bytes_be`.
- Produces: `Format::dec` handled by `decode`/`encode` instead of throwing. This is the one place decimal↔binary conversion exists; `dec` delegates rather than reimplementing, which is why it waited for Task 12.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_codec.cpp`)

```cpp
void run_codec_dec_tests() {
    CT_CHECK_EQ(decode(Format::dec, "256"), Bytes({0x01, 0x00}));
    CT_CHECK_EQ(encode(Format::dec, Bytes({0x01, 0x00})), std::string("256"));
    CT_CHECK_EQ(decode(Format::dec, "0"), Bytes{});            // zero carries no bytes
    CT_CHECK_EQ(encode(Format::dec, Bytes{}), std::string("0"));
    CT_CHECK_EQ(decode(Format::dec, " 1 234\n"), decode(Format::dec, "1234"));  // whitespace skipped
    CT_CHECK_THROWS(decode(Format::dec, "-1"), cryptrift::Error);
    CT_CHECK_THROWS(decode(Format::dec, "12a"), cryptrift::Error);
    CT_CHECK_EQ(encode(Format::dec, decode(Format::hex, "ff00ff00ff00ff00ff")),
                Bignum::from_hex("ff00ff00ff00ff00ff").to_dec());
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL on the first assertion.

- [ ] **Step 3: Implement** the `dec` branches and delete the placeholder throw. Document the asymmetry already stated in the spec: `dec` denotes a value, so leading zeroes do not survive a round trip through it.

- [ ] **Step 4: Run to verify it passes** — expected PASS, and `run_cli("base conv --in-format dec --out-format hex 255")` now returns `ff` with exit 0. Update the Task 4 assertion that expected exit 2 for `dec`.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): decimal format via bignum"`

---

## Task 15: `rsa` — parameters, encrypt, decrypt

**Files:**
- Create: `include/cryptrift/rsa.hpp`, `src/core/rsa.cpp`, `tests/test_rsa.cpp`
- Modify: `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`

**Interfaces:**
- Consumes: `bignum`, `Error`.
- Produces:
```cpp
struct KeyParams { Bignum n; Bignum phi; Bignum d; };
KeyParams params(const Bignum& p, const Bignum& q, const Bignum& e);  // throws when gcd(e, phi) != 1
Bignum encrypt(const Bignum& m, const Bignum& e, const Bignum& n);
Bignum decrypt(const Bignum& c, const Bignum& d, const Bignum& n);
```

- [ ] **Step 1: Write the failing tests** in `tests/test_rsa.cpp`

```cpp
void run_rsa_basic_tests() {
    const KeyParams k = params(Bignum(61), Bignum(53), Bignum(17));   // textbook values
    CT_CHECK_EQ(k.n.to_dec(),   std::string("3233"));
    CT_CHECK_EQ(k.phi.to_dec(), std::string("3120"));
    CT_CHECK_EQ(k.d.to_dec(),   std::string("2753"));
    CT_CHECK_EQ(encrypt(Bignum(65), Bignum(17), k.n).to_dec(), std::string("2790"));
    CT_CHECK_EQ(decrypt(Bignum(2790), k.d, k.n).to_dec(),      std::string("65"));

    CT_CHECK_THROWS(params(Bignum(61), Bignum(53), Bignum(2)), cryptrift::Error);  // gcd(2, 3120) = 2
    CT_CHECK_THROWS(params(Bignum(61), Bignum(53), Bignum(0)), cryptrift::Error);
    CT_CHECK_THROWS(params(Bignum(0),  Bignum(53), Bignum(17)), cryptrift::Error);

    // realistic size: a full cycle with 256-bit primes, from the spec's success criteria
    const Bignum p = Bignum::from_dec(/* 256-bit prime */), q = Bignum::from_dec(/* another */);
    const KeyParams big = params(p, q, Bignum(65537));
    const Bignum m = Bignum::from_bytes_be(from_string("flag{rsa_at_real_size}"));
    CT_CHECK_EQ(decrypt(encrypt(m, Bignum(65537), big.n), big.d, big.n).to_hex(), m.to_hex());
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement** `src/core/rsa.cpp`: `phi = (p-1)(q-1)`, `d = modinv(e, phi)`, and `encrypt`/`decrypt` as `modpow`. Reject `p` or `q` of zero or one, and let `modinv`'s own `Error` surface when `e` shares a factor with `phi`.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): RSA parameters, encrypt and decrypt"`

---

## Task 16: `rsa` — small-exponent root and common modulus

**Files:**
- Modify: `include/cryptrift/rsa.hpp`, `src/core/rsa.cpp`, `tests/test_rsa.cpp`

**Interfaces:**
- Consumes: `iroot`, `modinv`, `modpow`, `gcd`.
- Produces:
```cpp
std::optional<Bignum> small_e_root(const Bignum& c, std::uint32_t e);
Bignum common_modulus(const Bignum& n, const Bignum& e1, const Bignum& c1,
                      const Bignum& e2, const Bignum& c2);   // throws Error when gcd(e1, e2) != 1
```

- [ ] **Step 1: Write the failing tests** (append to `tests/test_rsa.cpp`)

```cpp
void run_rsa_attack_tests() {
    // m^e < n, so the ciphertext is a perfect cube
    const Bignum m = Bignum::from_bytes_be(from_string("flag{small_e}"));
    const Bignum c = mul(mul(m, m), m);
    const auto root = small_e_root(c, 3);
    CT_CHECK(root.has_value());
    CT_CHECK_EQ(root->to_hex(), m.to_hex());

    // not a perfect power: a no-result, not an error and not a wrong answer
    CT_CHECK(!small_e_root(add(c, Bignum(1)), 3).has_value());
    CT_CHECK(!small_e_root(Bignum(2), 3).has_value());
    CT_CHECK(small_e_root(Bignum(0), 3).has_value());

    const KeyParams k = params(Bignum::from_dec(/* 256-bit prime */),
                               Bignum::from_dec(/* another */), Bignum(65537));
    const Bignum e1(17), e2(65537);
    const Bignum msg = Bignum::from_bytes_be(from_string("flag{common_modulus}"));
    const Bignum recovered = common_modulus(k.n, e1, encrypt(msg, e1, k.n),
                                                 e2, encrypt(msg, e2, k.n));
    CT_CHECK_EQ(recovered.to_hex(), msg.to_hex());
    CT_CHECK_THROWS(common_modulus(k.n, Bignum(4), Bignum(1), Bignum(6), Bignum(1)),
                    cryptrift::Error);                 // gcd(4, 6) = 2
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** `small_e_root` returns `iroot(c, e).root` only when `exact` is true, and `std::nullopt` otherwise. `common_modulus` runs the extended Euclid on `e1`, `e2` to get coefficients `a`, `b` with `a*e1 + b*e2 = 1`, then combines `c1^a * c2^b mod n`, using `modinv` on whichever ciphertext carries the negative coefficient. Before returning, re-encrypt the recovered message under `e1` and compare against `c1`; a mismatch is an `Error`, since arriving here with a wrong value means the inputs were not a genuine common-modulus pair.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): small-exponent root and common-modulus attacks"`

---

## Task 17: `rsa` — Wiener's attack, self-verifying

**Files:**
- Modify: `include/cryptrift/rsa.hpp`, `src/core/rsa.cpp`, `tests/test_rsa.cpp`

**Interfaces:**
- Consumes: `divmod`, `modpow`, `iroot`.
- Produces: `std::optional<Bignum> wiener(const Bignum& n, const Bignum& e);`

This is the task the spec's central rule exists for: **a `d` is returned only after it has been verified.** The continued-fraction expansion offers many candidates and most are wrong; returning the first one that merely looks plausible is exactly the "reports success while holding garbage" failure.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_rsa.cpp`)

```cpp
void run_rsa_wiener_tests() {
    // a key with d small enough for Wiener to reach
    const Bignum n = Bignum::from_dec(/* n of a key built so that d < n^0.25 */);
    const Bignum e = Bignum::from_dec(/* its public exponent */);
    const Bignum d = Bignum::from_dec(/* its private exponent */);
    const auto found = wiener(n, e);
    CT_CHECK(found.has_value());
    CT_CHECK_EQ(found->to_dec(), d.to_dec());
    const Bignum probe = Bignum(42);
    CT_CHECK_EQ(modpow(modpow(probe, e, n), *found, n).to_dec(), std::string("42"));

    // a safe key: Wiener must give up, not return something unverified
    const KeyParams safe = params(Bignum::from_dec(/* 256-bit prime */),
                                  Bignum::from_dec(/* another */), Bignum(65537));
    CT_CHECK(!wiener(safe.n, Bignum(65537)).has_value());

    CT_CHECK(!wiener(Bignum(3233), Bignum(17)).has_value());   // textbook key, d not small
    CT_CHECK_THROWS(wiener(Bignum(0), Bignum(17)), cryptrift::Error);
    CT_CHECK_THROWS(wiener(Bignum(3233), Bignum(0)), cryptrift::Error);
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** Expand `e/n` as a continued fraction, build the convergents `k/d`, and for each one with `k != 0` compute `phi = (e*d - 1) / k`; discard it unless the division is exact. Solve `x^2 - (n - phi + 1)x + n = 0` for integer roots via `iroot` on the discriminant, confirming `p*q == n`. Only then verify with `modpow(modpow(probe, e, n), d, n) == probe` for a fixed probe coprime with `n`, and return `d`. Every candidate failing any check is skipped; exhausting the convergents returns `std::nullopt`.

- [ ] **Step 4: Run to verify it passes** — expected PASS. The safe-key assertion is the important one: confirm it fails if the verification step is removed, by deleting that check temporarily and watching the test go red.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): Wiener attack that verifies before reporting a key"`

---

## Task 18: CLI `rsa` group

**Files:**
- Create: `src/cli/cmd_rsa.cpp`
- Modify: `src/cli/render.hpp`, `src/cli/render.cpp`, `src/cli/commands.hpp`, `CMakeLists.txt`, `tests/test_cli.cpp`

**Interfaces:**
- Consumes: `rsa`, `Bignum`, `require`.
- Produces: `Bignum flag_bignum(const Args&, const std::string& flag);` — accepts decimal, or hex with a `0x` prefix, and throws `Error` on anything else.
  Commands: `rsa params --p --q --e`, `rsa encrypt --m --e --n`, `rsa decrypt --c --n` with either `--d` or `--p --q --e`, `rsa smalle --c --e`, `rsa common-modulus --n --e1 --c1 --e2 --c2`, `rsa wiener --n --e`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.cpp`)

```cpp
void run_cli_rsa_tests() {
    Run r = run_cli("rsa params --p 61 --q 53 --e 17");
    CT_CHECK_EQ(r.exit_code, 0);
    CT_CHECK(r.out.find("3233") != std::string::npos);       // n
    CT_CHECK(r.out.find("2753") != std::string::npos);       // d
    CT_CHECK_EQ(run_cli("rsa decrypt --c 2790 --n 3233 --d 2753").out, std::string("65\n"));
    CT_CHECK_EQ(run_cli("rsa decrypt --c 2790 --p 61 --q 53 --e 17").out, std::string("65\n"));
    CT_CHECK_EQ(run_cli("rsa encrypt --m 0x41 --e 17 --n 3233").exit_code, 0);  // hex input accepted

    CT_CHECK_EQ(run_cli("rsa wiener --n 3233 --e 17").exit_code, 1);            // gave up, honestly
    CT_CHECK(run_cli("rsa wiener --n 3233 --e 17").err.find("no") != std::string::npos);
    CT_CHECK_EQ(run_cli("rsa smalle --c 8 --e 3").out, std::string("2\n"));
    CT_CHECK_EQ(run_cli("rsa smalle --c 9 --e 3").exit_code, 1);                // no exact root
    CT_CHECK_EQ(run_cli("rsa params --p 61 --q 53 --e 2").exit_code, 2);
    CT_CHECK_EQ(run_cli("rsa params --p 61 --q 53").exit_code, 2);              // --e missing
    CT_CHECK_EQ(run_cli("rsa params --p 61 --q 53 --e 0x1g").exit_code, 2);
    CT_CHECK_EQ(run_cli("rsa decrypt --c 2790 --n 3233").exit_code, 2);         // neither d nor p/q/e
}
```

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** Numeric results print as decimal with a trailing newline; `--out-format hex` prints hex instead, and `--out-format raw` writes `to_bytes_be()` through `write_raw`, which is what turns a recovered RSA plaintext back into a flag. `rsa params` prints `n`, `phi` and `d` one per line, each labelled. A `std::nullopt` from `smalle` or `wiener` is `kNoResult` with a message on stderr.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit and push** — `git commit -m "feat(cli): rsa group"`, then `gh run watch`.

---

## Task 19: `analyze` — reconnaissance on an unknown blob

**Files:**
- Create: `include/cryptrift/analyze.hpp`, `src/core/analyze.cpp`, `src/cli/cmd_analyze.cpp`, `tests/test_analyze.cpp`
- Modify: `src/cli/render.hpp`, `src/cli/render.cpp`, `src/cli/commands.hpp`, `CMakeLists.txt`, `tests/tests.hpp`, `tests/main.cpp`, `tests/test_cli.cpp`

**Interfaces:**
- Consumes: `Bytes`, `codec`, `score`.
- Produces:
```cpp
struct Report {
    std::array<std::size_t, 256> counts;
    double index_of_coincidence;     // 0.0 for inputs shorter than 2 bytes
    double printable_ratio;
    std::vector<Format> likely_encodings;   // most likely first; may be empty
};
Report analyze(const Bytes& data);
void render_report(std::ostream& out, const Report& r);
```

- [ ] **Step 1: Write the failing tests** in `tests/test_analyze.cpp`

```cpp
void run_analyze_tests() {
    const Report english = analyze(from_string(/* ~300 chars of English prose */));
    CT_CHECK(english.index_of_coincidence > 0.055);          // English sits near 0.067
    CT_CHECK_EQ(english.printable_ratio, 1.0);
    CT_CHECK_EQ(english.counts[static_cast<unsigned char>('e')] > 0, true);

    Bytes flat(2600);                                        // uniform bytes
    for (std::size_t i = 0; i < flat.size(); ++i) flat[i] = static_cast<std::uint8_t>(i % 256);
    CT_CHECK(analyze(flat).index_of_coincidence < english.index_of_coincidence);

    const auto hexish = analyze(from_string("deadbeefcafebabe"));
    CT_CHECK(std::find(hexish.likely_encodings.begin(), hexish.likely_encodings.end(), Format::hex)
             != hexish.likely_encodings.end());
    const auto b64ish = analyze(from_string("Zm9vYmFyZm9vYmFy"));
    CT_CHECK(std::find(b64ish.likely_encodings.begin(), b64ish.likely_encodings.end(), Format::b64)
             != b64ish.likely_encodings.end());

    // Review Focus 3 again, at the last module that divides by a length
    const Report empty = analyze(Bytes{});
    CT_CHECK_EQ(empty.index_of_coincidence, 0.0);
    CT_CHECK_EQ(empty.printable_ratio, 0.0);
    CT_CHECK(empty.likely_encodings.empty());
    CT_CHECK_EQ(analyze(from_string("a")).index_of_coincidence, 0.0);
}
```
Plus in `tests/test_cli.cpp`: `run_cli("analyze deadbeef").exit_code == 0` and its output mentions `hex`; `run_cli("analyze --in-format hex zz").exit_code == 2`.

- [ ] **Step 2: Run to verify it fails** — expected FAIL to compile.

- [ ] **Step 3: Implement.** Index of coincidence over the 256-byte histogram with the `n(n-1)` denominator guarded for `n < 2`. `likely_encodings` reports a format when every non-whitespace byte belongs to that alphabet and the length constraint holds (even for hex, a multiple of 4 for base64), ordered by how restrictive the alphabet is, so `hex` precedes `b64`. `render_report` prints the ratios, the IoC, the likely encodings, and the ten most frequent bytes.

- [ ] **Step 4: Run to verify it passes** — expected PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: analyze command for unknown blobs"`

---

## Task 20: Documentation and the v0.1.0 release

**Files:**
- Modify: `README.md`
- Create: `docs/usage.md`, `docs/design.md`, `docs/release-notes-v0.1.0.md`

**Interfaces:**
- Consumes: every command shipped in Tasks 4–19.
- Produces: no code.

- [ ] **Step 1: Write the check first**

Add to `tests/test_cli.cpp` a test that every group named in the README's command table answers `--help`-style dispatch with exit 0:
```cpp
void run_cli_help_tests() {
    for (const char* group : {"base", "xor", "caesar", "affine", "rsa", "analyze"}) {
        const Run r = run_cli(std::string("help ") + group);
        CT_CHECK_EQ(r.exit_code, 0);
        CT_CHECK(!r.out.empty());
    }
}
```
This keeps the documented surface and the real surface from drifting apart.

- [ ] **Step 2: Run to verify it fails** — expected FAIL for any group whose help text is missing.

- [ ] **Step 3: Write the documentation**

`README.md`: badges; the spec's one-line purpose; a 60-second build (`cmake -S . -B build && cmake --build build`); three worked examples that are real CTF motions — crack a single-byte XOR from hex, crack an affine ciphertext, recover a flag with `rsa wiener` piped through `--out-format raw`; the full command table; the exit-code table; a "what this is not" section naming the §1 non-goals so nobody files an issue asking for AES; and a note that this is a learning project whose bignum is not constant-time and must not be used for production cryptography.

`docs/usage.md`: every command with its flags, its exit codes, and one example each, including the `--min-printable` and `--top` tuning knobs and a pipeline example using `-q`.

`docs/design.md`: the architecture a contributor needs — the module dependency order, the `src/core/` no-I/O rule, and the invalid-input-versus-no-result split — linking to the full spec rather than restating it.

`docs/release-notes-v0.1.0.md`: what ships, what it deliberately does not do, and the known limitation that `bignum` is schoolbook and not constant-time.

- [ ] **Step 4: Verify the examples**

Run every command block in the README and in `docs/usage.md` against the built binary and confirm the printed output matches what is documented, character for character. Then `ctest --test-dir build --output-on-failure`; expected PASS.

- [ ] **Step 5: Commit, push, tag**

```bash
git add -A && git commit -m "docs: README and usage guide for v0.1.0"
git push && gh run watch
git tag -a v0.1.0 -m "CryptRift v0.1.0: XOR, affine, RSA helpers and base conversions"
git push origin v0.1.0
gh release create v0.1.0 --title "CryptRift v0.1.0" --notes-file docs/release-notes-v0.1.0.md
```
Expected: CI green on the tag, release visible on the repo page.
