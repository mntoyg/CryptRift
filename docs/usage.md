# CryptRift usage

Every command, its flags, and one example each. The examples are run against the
built binary before each release, so what is printed here is what you get.

## Shared conventions

**Input** is taken from the first positional argument, or from `--in FILE`, or
from standard input when neither is given (a positional of `-` also means
stdin).

**Formats** apply to `--in-format` and `--out-format`, and both default to
`raw`:

| Name | Meaning |
|---|---|
| `raw` | Bytes as they are |
| `hex` | Two hex digits per byte. An optional leading `0x` and embedded whitespace are accepted |
| `b64` | Base64, RFC 4648 |
| `b32` | Base32, RFC 4648 |
| `bin` | Eight `0`/`1` characters per byte |
| `dec` | The whole input as **one non-negative integer in decimal** |

`dec` denotes a value rather than a byte string, so a leading zero byte does not
survive a round trip through it. That is what makes it the right format for an
RSA modulus and the wrong one for a file.

Decoding is strict about content and lenient about layout: a non-hex character
or bad base64 padding is an error, but a blob pasted across three lines is fine.
A blob that fails to decode is information, so it is never quietly repaired.

**Ranked commands** (`xor crack`, `caesar crack`, `affine crack`) share:

| Flag | Default | Meaning |
|---|---|---|
| `--top N` | `10` | How many candidates to show. `0` shows all |
| `--min-printable R` | `0.9` | Discard candidates whose printable-ASCII share is below `R`. `0` keeps everything |
| `-q`, `--quiet` | off | Print only the best candidate's bytes, raw, with no table and no trailing newline |

A value that does not parse completely is an error, not a default: `--top 10x`
is rejected rather than read as `10`.

**Exit codes** are `0` for a result, `1` for ran-correctly-and-found-nothing,
and `2` for a usage or input error. Diagnostics go to stderr prefixed
`cryptrift: `; stdout carries results only, so pipes stay clean.

## base

### `base conv`

```console
$ cryptrift base conv --in-format hex --out-format b64 4d7a
TXo=
$ cryptrift base conv --in-format hex --out-format dec ff
255
$ echo -n 4d7a | cryptrift base conv --in-format hex --out-format raw
Mz
```

## xor

### `xor apply`

Takes exactly one of `--key` (text) or `--key-hex`. Giving both, or neither, or
an empty key is an error. XOR is its own inverse, so this also decrypts.

```console
$ cryptrift xor apply --key-hex 5a --out-format hex abc
3b3839
```

### `xor crack`

Single-byte by default. Naming a key-length range switches to the
repeating-key search.

| Flag | Default | Meaning |
|---|---|---|
| `--keylen-min N` | — | Lowest key length to consider; its presence selects repeating-key mode |
| `--keylen-max N` | `40` | Highest key length to consider |

```console
$ cryptrift xor crack --in-format hex --top 3 0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427
rank  key                   score  plaintext
   1  5a                   138.18  The flag is flag{xor_is_not_encryption}
   2  50                   135.53  ^bo*lfkm*cy*lfkmqrexUcyUde~Uodixsz~cedw
   3  70                   135.53  ~BO.LFKM.CY.LFKMQREXuCYuDE^uODIXSZ^CEDW
```

Candidates are ranked by how English-like the plaintext is, **less one point per
key byte**. That penalty matters: a longer key has more free bytes, so solving
each column independently can push a nonsense plaintext above the real one. On a
69-byte ciphertext with a 4-byte key, three over-fitted keys of 15 and 16 bytes
scored above the true answer before the penalty was added.

The recovered key is also reduced to its smallest period, so a correct plaintext
is never reported under a doubled key such as `RIFTRIFT`.

Pipe the winner into something else with `-q`:

```console
$ cryptrift xor crack -q --in-format hex 0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427
The flag is flag{xor_is_not_encryption}
```

### `xor crib`

Drags a known fragment across the ciphertext and shows the key bytes each
offset would imply. `--crib` is required; `--crib-format` defaults to `raw`.

```console
$ cryptrift xor crib --crib flag{ --in-format hex --top 3 0e323f7a3c363b3d7a33297a3c363b3d212235280533290534352e053f343928232a2e33353427
```

## caesar

### `caesar apply`

`--shift N` is required and may be negative or larger than 26.

```console
$ echo -n "attack at dawn" | cryptrift caesar apply --shift 3
dwwdfn dw gdzq
```

### `caesar crack`

All 26 shifts, ranked. The key is reported **as it was applied**, so cracking
text that was shifted by 7 answers `b=7`, the way a challenge states it.

```console
$ echo -n "dwwdfn dw gdzq" | cryptrift caesar crack -q
attack at dawn
```

## affine

`E(x) = (a·x + b) mod 26`, over A–Z and a–z, leaving every other byte alone.
`a` must be coprime with 26; anything else is an error rather than a cipher
nobody can undo.

### `affine apply` and `affine decrypt`

Both require `--a` and `--b`.

```console
$ echo -n "the eagle has landed" | cryptrift affine apply --a 5 --b 8
zrc cimlc riu livxcx
```

### `affine crack`

All 312 keys — the twelve valid multipliers times 26 shifts.

```console
$ echo -n "Wklv lv d whvw phvvdjh iru wkh fudfnhu" | cryptrift affine crack -q
This is a test message for the cracker
```

## rsa

Numbers may be given in decimal, or in hex with an explicit `0x`. A bare `41` is
forty-one, never `0x41`.

Output here defaults to **decimal**, not raw, because an RSA result is a number.
`--out-format hex` and `--out-format raw` are also accepted, and `raw` is what
turns a recovered message back into a flag.

### `rsa params`

```console
$ cryptrift rsa params --p 61 --q 53 --e 17
n   = 3233
phi = 3120
d   = 2753
```

An exponent sharing a factor with `phi` has no private counterpart, so this
errors rather than reporting a `d` that cannot decrypt. Equal `p` and `q` are
rejected too: `phi = (p-1)(q-1)` is simply wrong there.

### `rsa encrypt` and `rsa decrypt`

```console
$ cryptrift rsa encrypt --m 65 --e 17 --n 3233
2790
$ cryptrift rsa decrypt --c 2790 --n 3233 --d 2753
65
$ cryptrift rsa decrypt --c 2790 --p 61 --q 53 --e 17
65
```

`decrypt` needs either `--d --n` or `--p --q --e`; neither is an error.

### `rsa smalle`

For an unpadded message small enough that `m^e` never wrapped `n`, so the
ciphertext is a perfect `e`-th power.

```console
$ cryptrift rsa smalle --c 534362316273970181549588003507266739265499754799160081099504986457180500546068085545023534181 --e 3 --out-format raw
flag{small_e}
```

When the ciphertext is **not** a perfect power the attack does not apply, and
the command says so and exits `1`. It never reports the floor of the root as if
it were the message:

```console
$ cryptrift rsa smalle --c 9 --e 3
cryptrift: no exact root found
$ echo $?
1
```

### `rsa common-modulus`

One message encrypted twice under one modulus with coprime exponents.

```console
$ cryptrift rsa common-modulus --n N --e1 17 --c1 C1 --e2 65537 --c2 C2 --out-format raw
```

Exponents that share a factor cannot support the attack and are a usage error.
The recovered value is re-encrypted and compared against `--c1` before anything
is printed, so two ciphertexts that are not a genuine pair produce an error
rather than a number that merely looks like a flag.

### `rsa wiener`

Recovers `d` when it is small relative to `n`, by walking the convergents of the
continued fraction of `e/n`.

```console
$ cryptrift rsa wiener --n 3233 --e 17
cryptrift: no private exponent found
$ echo $?
1
```

That is the interesting case. The expansion offers many candidate exponents and
nearly all of them are wrong, so each one must divide `e·d − 1` exactly, imply a
quadratic that factors `n`, **and** round-trip a probe message. When no
candidate survives, the command reports nothing and exits `1`.

## analyze

Reconnaissance on a blob you know nothing about. Takes no subcommand.

```console
$ cryptrift analyze deadbeefcafebabe
length            16 bytes
printable         1.000
coincidence index 0.15000  (English prose is around 0.06-0.07, flat data 0.003)
looks like        hex, b64
most common bytes
  65  e  5
  61  a  3
  62  b  3
...
```

The coincidence index is computed over the whole byte histogram. Measured on the
same English sample it gives 0.072, against 0.064 for the letters alone and
0.0035 for flat data — so the gap, not the absolute figure, is the signal.

Encoding guesses check length as well as alphabet, so an odd number of hex
digits is never offered as hex, and they are ordered by how restrictive the
alphabet is, so a blob that both hex and base64 would accept is reported as hex
first.
