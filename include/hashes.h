/*
 * hashes.h — shared signatures for every hash algorithm exercised by
 * the benchmark. All implementations are plain C with no platform
 * dependencies, so the same .c files compile on GBDK (Z80/SM83),
 * devkitARM/libtonc (GBA ARM7TDMI), devkitARM/libnds (NDS ARM946E),
 * and devkitARM/libctru (3DS ARM11).
 *
 * Each algorithm is a one-shot "hash this buffer" function; the
 * benchmark harness times the inner loop, not context setup. Per-
 * algorithm metadata (label, digest size, iteration count) lives in
 * `ALGOS[]` in source/main.c.
 *
 * The HBENCH_BANKED attribute lets the GB build place big code
 * (BLAKE2s / RIPEMD-160 / HMAC-SHA256) in banks 2/3 and call them
 * through SDCC's banked-call ABI; on GBA / NDS / 3DS / host it
 * collapses to nothing.
 */
#ifndef HASHES_H
#define HASHES_H

#include <stdint.h>

#ifdef __SDCC
#  ifdef __PORT_sm83
#    include <asm/sm83/types.h>
#  endif
#  ifndef HBENCH_BANKED
#    define HBENCH_BANKED  BANKED
#  endif
#endif
#ifndef HBENCH_BANKED
#  define HBENCH_BANKED
#endif

/* Largest digest size across all algorithms (SHA-512 / SHA-3-512 = 64 bytes). */
#define HASH_MAX_DIGEST 64u

/* Workload buffer size. */
#define BENCH_BUF_LEN   1024u

/* ---- tiny non-cryptographic ------------------------------------------ */
void hash_crc8        (const uint8_t *data, uint16_t len, uint8_t out[1])  HBENCH_BANKED;
void hash_crc16       (const uint8_t *data, uint16_t len, uint8_t out[2])  HBENCH_BANKED;
void hash_crc32       (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_crc64       (const uint8_t *data, uint16_t len, uint8_t out[8])  HBENCH_BANKED;
void hash_adler32     (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_fletcher16  (const uint8_t *data, uint16_t len, uint8_t out[2])  HBENCH_BANKED;
void hash_fletcher32  (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_fletcher64  (const uint8_t *data, uint16_t len, uint8_t out[8])  HBENCH_BANKED;
void hash_djb2        (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_fnv1a32     (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_pearson     (const uint8_t *data, uint16_t len, uint8_t out[1])  HBENCH_BANKED;
void hash_knuth       (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_jenkins_oat (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_pjw_elf     (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_sdbm        (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;

/* ---- non-cryptographic (heavier) ------------------------------------- */
void hash_murmur3     (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_murmur3_128 (const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED;
void hash_xxh32       (const uint8_t *data, uint16_t len, uint8_t out[4])  HBENCH_BANKED;
void hash_xxh64       (const uint8_t *data, uint16_t len, uint8_t out[8])  HBENCH_BANKED;
void hash_siphash24   (const uint8_t *data, uint16_t len, uint8_t out[8])  HBENCH_BANKED;

/* ---- cryptographic --------------------------------------------------- */
void hash_md4         (const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED;
void hash_md5         (const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED;
void hash_ripemd160   (const uint8_t *data, uint16_t len, uint8_t out[20]) HBENCH_BANKED;
void hash_sha1        (const uint8_t *data, uint16_t len, uint8_t out[20]) HBENCH_BANKED;
void hash_sha256      (const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED;
void hash_sha3_256    (const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED;
void hash_blake2s     (const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED;
void hash_sha512      (const uint8_t *data, uint16_t len, uint8_t out[64]) HBENCH_BANKED;
void hash_sha3_512    (const uint8_t *data, uint16_t len, uint8_t out[64]) HBENCH_BANKED;
void hash_hmac_sha256 (const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED;
void hash_pbkdf2_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED;
void hash_aes_cbc_mac (const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED;

#endif
