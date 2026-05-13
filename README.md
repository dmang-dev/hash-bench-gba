# hash-bench-gba

Native **Game Boy Advance** hashing-algorithm benchmark. **32
algorithms** — 20 non-cryptographic checksums + hashes (CRC-8/16/32/64,
Adler-32, Fletcher-16/32/64, DJB2, FNV-1a, Pearson-8, Knuth, Jenkins
one-at-a-time, PJW/ELF, SDBM, Murmur3-32, MurmurHash3-128, xxHash32,
xxHash64, SipHash-2-4) and 12 cryptographic (MD4, MD5, RIPEMD-160,
SHA-1, SHA-256, SHA-3-256, SHA-3-512, BLAKE2s, SHA-512, HMAC-SHA256,
PBKDF2-HMAC-SHA256, AES-CBC-MAC), hashing the same 1024-byte workload
buffer used by the sibling GB and NDS projects, timed with the GBA's
cascaded hardware timers at full bus-clock resolution (16.78 MHz,
~60 ns per cycle).

Results table is **paginated** — 8 rows per page across **4 pages**;
**LEFT/RIGHT** to flip pages, **B** to re-run the sweep. Per-page
themes: tiny checksums → tiny dispersing hashes → modern non-crypto →
cryptographic.

Sibling to [`totp-gba`](https://github.com/dmang-dev/totp-gba), [`hash-bench-gb`](https://github.com/dmang-dev/hash-bench-gb)
(23 algos on SM83), [`hash-bench-nds`](https://github.com/dmang-dev/hash-bench-nds) (same 32
algos, dual-screen layout on ARM946E @ 33.5 MHz),
[`hash-bench-dsi`](https://github.com/dmang-dev/hash-bench-dsi) (same 32 algos on DSi-mode
ARM946E @ 134 MHz), and [`hash-bench-3ds`](https://github.com/dmang-dev/hash-bench-3ds) (same 32
algos on ARM11 @ 268-804 MHz native libctru).

[![ROM](https://img.shields.io/badge/ROM-prebuilt%20%26%20committed-success)](artifacts/)
[![Built with devkitARM](https://img.shields.io/badge/built%20with-devkitARM-orange)](https://devkitpro.org)

---

## What it does

On boot:

1. Initializes a phosphor-green palette + 8x8 libtonc text engine
2. Initializes cascaded TM0+TM1 (full 32-bit counter at 16.78 MHz)
3. Fills a 1024-byte buffer with `i*31+7` (mod 256)
4. For each algorithm, runs N iterations and reports microseconds per
   iteration + KB/s throughput

Press **B** to re-run.

Every result row is also pushed to the mGBA debug-log register so you
can grep CI runs (`tools > scripting` style) without screen-scraping
the LCD.

---

## Try it

Pre-built ROM in [`artifacts/`](artifacts/):

| File | Target | Notes |
|---|---|---|
| `hash-bench-gba.gba` | GBA / GBA SP / GBA Micro / DS / DS Lite / DSi (slot-2) | Native ARM7 build, ~58 KB |

Load it in **mGBA** or any GBA emulator, or flash to a slot-2 cart.
No SRAM, no save data — everything's in ROM and IWRAM.

---

## Build from source

Requires **devkitPro** with `gba-dev` (devkitARM + libgba + libtonc):
https://github.com/devkitPro/installer/releases.

```
.\build.bat            # build hash-bench-gba.gba and copy to artifacts\
.\build.bat clean      # nuke build/ + outputs
```

The build script forces Windows-style devkitPro paths even if your
environment has them set to msys / POSIX style, which is needed when
invoking from PowerShell.

Linux/macOS / CI: `make` works directly.

---

## Algorithms

Identical set as the sibling GB project — every `.c` file under
[`source/`](source/) (except `main.c`, `mgba_log.c`, `bench_timer.c`)
is byte-identical to its counterpart in
[`../hash-bench-gb/src/`](https://github.com/dmang-dev/hash-bench-gb/tree/main/src/).

| Algorithm | Type | Digest | Notes |
|---|---|---|---|
| CRC-8/SMBUS   | checksum | 8 bit  | Poly 0x07, bit-by-bit, no table |
| CRC-16/XMODEM | checksum | 16 bit | Poly 0x1021, bit-by-bit, no table |
| CRC-32/IEEE   | checksum | 32 bit | Poly 0xEDB88320, bit-by-bit, reflected |
| Adler-32      | checksum | 32 bit | Two 16-bit accumulators mod 65521 |
| DJB2          | non-crypto | 32 bit | `h = ((h<<5)+h) + c`, init 5381 |
| FNV-1a 32     | non-crypto | 32 bit | One 32×32 multiply per byte |
| Pearson-8     | non-crypto | 8 bit  | 256-byte permutation table; one xor + one load per byte |
| Murmur3-32    | non-crypto | 32 bit | 4-byte block ARX with `fmix32` finalizer (seed 0) |
| xxHash32      | non-crypto | 32 bit | Four-lane ARX (multiply-heavy) |
| **xxHash64**  | non-crypto | 64 bit | 64-bit successor; four-lane ARX. Workhorse of LZ4/Zstd/RocksDB |
| **SipHash-2-4** | non-crypto keyed | 64 bit | Default hash inside Python `dict`, Rust `HashMap`, Perl. Modern minimal MAC |
| MD4           | cryptographic *(broken)* | 128 bit | RFC 1320, 64-byte block, 3 rounds × 16 ops |
| MD5           | cryptographic | 128 bit | 64-byte block, 64 rounds |
| **RIPEMD-160** | cryptographic | 160 bit | Twin-pipeline 5×16 rounds, Bitcoin's address hash |
| SHA-1         | cryptographic | 160 bit | 64-byte block, 80 rounds |
| SHA-256       | cryptographic | 256 bit | 64-byte block, 64 rounds |
| **SHA-3-256** | cryptographic | 256 bit | Keccak-f[1600] permutation, sponge construction |
| BLAKE2s-256   | cryptographic | 256 bit | RFC 7693, 64-byte block, 10 rounds × 8 G-mixes |
| **SHA-512**   | cryptographic | 512 bit | 128-byte block, 80 rounds, all 64-bit math |
| **HMAC-SHA256** | crypto MAC | 256 bit | RFC 2104; two SHA-256 calls per invocation |

The ARM7 has a single-cycle barrel-shifter and a hardware multiply
unit, so the multiply-heavy algorithms (FNV-1a, Murmur3, xxHash32)
that look slow on the GB are actually faster than the bit-shifty CRCs
here. BLAKE2s usually edges out SHA-256 on this CPU because its G
function maps cleanly to ARM's `add Rd, Rn, Rm, ror #n` form.

### Reference digests

Workload buffer: `buf[i] = (i * 31 + 7) & 0xFF` for `i` in `[0, 1024)`.

| Algorithm   | Digest |
|---|---|
| CRC-8       | `DD` |
| CRC-16      | `F009` |
| CRC-32      | `7C321B5D` |
| Adler-32    | `13D3FE10` |
| DJB2        | `358B5305` |
| FNV-1a 32   | `2C6D0DC5` |
| Pearson-8   | `A0` |
| Murmur3-32  | `56530DF1` |
| xxHash64    | `149AA44972CDAE00` (LE: stored bytes are `00 AE CD 72 …`) |
| SipHash-2-4 | `12AB28BE1797B5D6` (LE; key = bytes 0x00..0x0F) |
| MD4         | `A2909A641975A5CB590984B5323BB03B` |
| MD5         | `63B2177A7AF739B5CC52AB1D1C714702` |
| RIPEMD-160  | `21D1D63F50CDF5CACD90D8B323D22D0E7EAB00D2` |
| SHA-1       | `B66786CDE756750241D1F0EAB86CE6F81855B017` |
| SHA-256     | `8D7E566766F6BD1BB4CAC87CADFDE681197F9243F4D2692A0FD12674092212A7` |
| SHA-3-256   | `D925394CF5841554B9FC100363BD6EB55E69CD166C164C11EE5F699F181219BD` |
| BLAKE2s-256 | `AD41D5E917BE8E9CD95975E72CF44E118268294566BD95D7FCEB3D23D200EDC8` |
| SHA-512     | `076291378444AC54F7E7AC5717C498F169218B3BA608D08A3FA63E56063C4A9E0E26EA6FC82654B79AADB9E70AE90D5401DE36A0DF9B4B2DD046B7BAD4E4DA32` |
| HMAC-SHA256 | `CE139393FFB45956D62726B112E7F34C538104578DB59F75B564F1AF764BB3BD` (key = `hash-bench-nds` + 2 zero bytes) |

The displayed row shows the first four bytes of each digest; the mGBA
log row shows the full digest in hex. Single-byte algorithms (CRC-8,
Pearson-8) display the byte followed by `000000` because the digest
buffer is zeroed before each call.

---

## Timing methodology

Two cascaded hardware timers — `REG_TM0` ticks every system clock,
`REG_TM1` cascade-counts TM0 overflows — give a 32-bit free-running
counter at 16.78 MHz that wraps every ~256 seconds. Read pattern is
the standard hi/lo/hi retry to avoid torn reads across a TM0 overflow
(see [`source/bench_timer.c`](source/bench_timer.c)).

For each algorithm:

```c
t0 = bench_timer_read();
for (k = 0; k < iters; k++) hash(buf, 1024, digest);
t1 = bench_timer_read();
us_per = (t1 - t0) * 1e6 / 16780000 / iters;
```

The iteration counts (50-400) are tuned so each algorithm runs ~50 ms
of wall time, giving 4-5 significant digits of microsecond precision
even after dividing by `iters`.

`KB/s` is computed against binary KB: `1e6 / us_per` for a 1024-byte
iteration.

---

## Layout

```
source/
  main.c                    Boot, sweep, paginated render, dispatch
  bench_timer.c             Cascaded TM0+TM1 cycle counter
  mgba_log.c                mGBA debug-log register wrapper
  crc8.c crc16.c crc32.c adler32.c                  non-crypto checksums
  djb2.c fnv1a.c pearson.c murmur3.c xxhash32.c     non-crypto hashes
  xxhash64.c siphash.c                              non-crypto, 64-bit
  md4.c md5.c sha1.c sha256.c blake2s.c             cryptographic
  ripemd160.c sha3.c sha512.c hmac_sha256.c         cryptographic, GBA-only
include/
  hashes.h bench_timer.h mgba_log.h
artifacts/                  Prebuilt ROM (committed)
Makefile                    devkitARM + libtonc + libgba
build.bat                   Windows wrapper (forces devkitPro paths)
```

Sixteen of the twenty hash `*.c` files are byte-identical to the GB
project's [`../hash-bench-gb/src/`](https://github.com/dmang-dev/hash-bench-gb/tree/main/src/); all twenty
are byte-identical to the NDS project's
[`../hash-bench-nds/source/`](https://github.com/dmang-dev/hash-bench-nds/tree/main/source/). The
`#pragma bank N` lines in `blake2s.c`, `ripemd160.c`, `hmac_sha256.c`
are gated on `#ifdef __PORT_sm83` so devkitARM ignores them.

---

## Acknowledgments

- [devkitPro / devkitARM](https://devkitpro.org/) — ARM toolchain
- [libtonc](https://www.coranac.com/tonc/text/) — GBA helper library /
  text engine
- [mGBA](https://mgba.io) — accurate emulator + debug interface
- [`totp-gba`](https://github.com/dmang-dev/totp-gba) — project template + mGBA log helpers
