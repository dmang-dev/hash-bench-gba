/*
 * hash-bench-gba — Game Boy Advance hashing-algorithm benchmark.
 *
 * 32 algorithms × 3 input sizes (64 / 256 / 1024 B) across 4 pages.
 *
 *   Single-size mode (default):  detailed view with digest + KB/s at 1024 B
 *   Matrix mode  (SELECT):        KB/s @ 64 / 256 / 1024 side-by-side
 *
 * Rows are tinted by tier — green=checksum, amber=non-crypto, cyan=crypto —
 * via per-row `tte_set_ink()` against a 4-color BG palette. (libtonc's
 * default tte_init_se_default renders glyphs with the current ink colour,
 * so changing ink between rows produces a row-coloured table.)
 *
 * Controls:
 *   B           — re-run sweep
 *   A           — cycle sort mode (category / by-speed / by-name)
 *   SELECT      — toggle single-size ↔ matrix view
 *   LEFT/RIGHT  — flip page
 */
#include <tonc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hashes.h"
#include "mgba_log.h"
#include "bench_timer.h"

/* ---- 4-color BG palette ---------------------------------------------- */
/* Phosphor-green theme matching the totp-gba / hash-bench-gba lineage.
 * Per-row coloring via tte_set_ink() was attempted but libtonc's TTE
 * SE-default renderer doesn't honour ink the way we expected — colour
 * by tier is deferred. For now everything renders in PHOS_BRIGHT
 * (palette index 1). The '*' marker on the fastest in each tier is
 * the only intra-row visual cue. */
#define PHOS_DARK       RGB15( 2,  4,  2)
#define PHOS_MID_LO     RGB15( 8, 14,  8)
#define PHOS_MID_HI     RGB15(15, 25, 15)
#define PHOS_BRIGHT     RGB15(24, 31, 24)

/* ---- workload buffer ------------------------------------------------ */
static uint8_t  buffer[BENCH_BUF_LEN];
static uint8_t  digest[HASH_MAX_DIGEST];

/* ---- algorithm table ------------------------------------------------ */
typedef void (*hash_fn)(const uint8_t *data, uint16_t len, uint8_t *out);

#define TIER_CHECKSUM   0u
#define TIER_NONCRYPTO  1u
#define TIER_CRYPTO     2u
#define NUM_TIERS       3u

typedef struct {
    const char *name;
    hash_fn     fn;
    uint8_t     digest_len;
    uint16_t    iters;
    uint8_t     tier;
} bench_algo;

static const bench_algo ALGOS[] = {
    /* page 0 — checksums + Fletcher */
    { "CRC8  ", hash_crc8,            1, 200u, TIER_CHECKSUM  },
    { "CRC16 ", hash_crc16,           2, 200u, TIER_CHECKSUM  },
    { "CRC32 ", hash_crc32,           4, 200u, TIER_CHECKSUM  },
    { "CRC64 ", hash_crc64,           8, 100u, TIER_CHECKSUM  },
    { "ADL32 ", hash_adler32,         4, 400u, TIER_CHECKSUM  },
    { "FLT16 ", hash_fletcher16,      2, 400u, TIER_CHECKSUM  },
    { "FLT32 ", hash_fletcher32,      4, 400u, TIER_CHECKSUM  },
    { "FLT64 ", hash_fletcher64,      8, 400u, TIER_CHECKSUM  },
    /* page 1 — dispersing tiny hashes */
    { "PRSN8 ", hash_pearson,         1, 800u, TIER_NONCRYPTO },
    { "KNUTH ", hash_knuth,           4, 400u, TIER_NONCRYPTO },
    { "OAT   ", hash_jenkins_oat,     4, 400u, TIER_NONCRYPTO },
    { "PJW   ", hash_pjw_elf,         4, 400u, TIER_NONCRYPTO },
    { "SDBM  ", hash_sdbm,            4, 400u, TIER_NONCRYPTO },
    { "DJB2  ", hash_djb2,            4, 400u, TIER_NONCRYPTO },
    { "FNV1A ", hash_fnv1a32,         4, 200u, TIER_NONCRYPTO },
    { "MMUR3 ", hash_murmur3,         4, 200u, TIER_NONCRYPTO },
    /* page 2 — modern non-crypto + early crypto */
    { "M3-128", hash_murmur3_128,    16, 200u, TIER_NONCRYPTO },
    { "XXH32 ", hash_xxh32,           4, 400u, TIER_NONCRYPTO },
    { "XXH64 ", hash_xxh64,           8, 400u, TIER_NONCRYPTO },
    { "SIP24 ", hash_siphash24,       8, 200u, TIER_NONCRYPTO },
    { "MD4   ", hash_md4,            16, 100u, TIER_CRYPTO    },
    { "MD5   ", hash_md5,            16, 100u, TIER_CRYPTO    },
    { "RMD160", hash_ripemd160,      20,  50u, TIER_CRYPTO    },
    { "SHA1  ", hash_sha1,           20, 100u, TIER_CRYPTO    },
    /* page 3 — heavy crypto */
    { "SHA256", hash_sha256,         32,  50u, TIER_CRYPTO    },
    { "SHA3  ", hash_sha3_256,       32,  30u, TIER_CRYPTO    },
    { "BLK2S ", hash_blake2s,        32,  50u, TIER_CRYPTO    },
    { "SHA512", hash_sha512,         64,  30u, TIER_CRYPTO    },
    { "SHA3L ", hash_sha3_512,       64,  20u, TIER_CRYPTO    },
    { "HSHA2 ", hash_hmac_sha256,    32,  30u, TIER_CRYPTO    },
    { "PBKDF2", hash_pbkdf2_sha256,  32,   5u, TIER_CRYPTO    },
    { "AESCBC", hash_aes_cbc_mac,    16, 100u, TIER_CRYPTO    }
};
#define NUM_ALGOS ((uint8_t)(sizeof(ALGOS) / sizeof(ALGOS[0])))

#define ROWS_PER_PAGE 8u
#define NUM_PAGES     ((uint8_t)((NUM_ALGOS + ROWS_PER_PAGE - 1u) / ROWS_PER_PAGE))

static const char *PAGE_SUBTITLE[NUM_PAGES] = {
    "checksums", "tiny hashes", "modern non-crypto", "cryptographic"
};

/* Buffer-size sweep. */
#define BENCH_SIZE_COUNT   3u
#define HEADLINE_SIZE_IDX  2u
static const uint16_t BENCH_SIZES[BENCH_SIZE_COUNT]      = {  64u, 256u, 1024u };
static const uint8_t  BENCH_SIZE_SCALE[BENCH_SIZE_COUNT] = {  16u,   4u,    1u };

typedef struct {
    uint32_t us_per;
    uint32_t kb_per_s;
    uint8_t  hash[4];
} bench_result;

static bench_result results[NUM_ALGOS][BENCH_SIZE_COUNT];
static uint8_t      fastest_in_tier_flag[NUM_ALGOS];
static uint8_t      current_page = 0u;

#define SORT_DEFAULT 0u
#define SORT_SPEED   1u
#define SORT_NAME    2u
#define NUM_SORT_MODES 3u
static uint8_t sort_mode = SORT_DEFAULT;
static uint8_t sort_indices[NUM_ALGOS];

#define MODE_SINGLE 0u
#define MODE_MATRIX 1u
static uint8_t display_mode = MODE_SINGLE;

static uint32_t total_us = 0u;

/* ---- helpers --------------------------------------------------------- */
static void fill_buffer(void) {
    uint16_t i;
    for (i = 0; i < BENCH_BUF_LEN; i++) {
        buffer[i] = (uint8_t)((i * 31u + 7u) & 0xFFu);
    }
}

static void hex8(char *dst, uint8_t b) {
    static const char H[] = "0123456789ABCDEF";
    dst[0] = H[(b >> 4) & 0x0Fu];
    dst[1] = H[b & 0x0Fu];
}
static void format_digest(char *dst, const uint8_t *d, uint8_t n) {
    uint8_t i;
    for (i = 0; i < n; i++) hex8(dst + (i * 2u), d[i]);
    dst[n * 2u] = '\0';
}

static const char *sort_label(void) {
    if (sort_mode == SORT_SPEED) return "spd";
    if (sort_mode == SORT_NAME)  return "abc";
    return "def";
}
static const char *mode_label(void) {
    return (display_mode == MODE_MATRIX) ? "matrix" : "single";
}

static int name_cmp6(const char *a, const char *b) {
    uint8_t i;
    for (i = 0; i < 6u; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* ---- sort + tier-fastest -------------------------------------------- */
static void compute_order(void) {
    uint8_t i, j, tmp;
    for (i = 0; i < NUM_ALGOS; i++) sort_indices[i] = i;

    if (sort_mode == SORT_SPEED) {
        for (i = 0; i < (uint8_t)(NUM_ALGOS - 1u); i++) {
            for (j = 0; j < (uint8_t)(NUM_ALGOS - 1u - i); j++) {
                if (results[sort_indices[j]    ][HEADLINE_SIZE_IDX].us_per >
                    results[sort_indices[j + 1u]][HEADLINE_SIZE_IDX].us_per) {
                    tmp = sort_indices[j];
                    sort_indices[j] = sort_indices[j + 1u];
                    sort_indices[j + 1u] = tmp;
                }
            }
        }
    } else if (sort_mode == SORT_NAME) {
        for (i = 0; i < (uint8_t)(NUM_ALGOS - 1u); i++) {
            for (j = 0; j < (uint8_t)(NUM_ALGOS - 1u - i); j++) {
                if (name_cmp6(ALGOS[sort_indices[j]].name,
                              ALGOS[sort_indices[j + 1u]].name) > 0) {
                    tmp = sort_indices[j];
                    sort_indices[j] = sort_indices[j + 1u];
                    sort_indices[j + 1u] = tmp;
                }
            }
        }
    }
}

static void compute_tier_flags(void) {
    uint32_t best[NUM_TIERS]    = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };
    uint8_t best_idx[NUM_TIERS] = { 0xFFu, 0xFFu, 0xFFu };

    for (uint8_t i = 0; i < NUM_ALGOS; i++) {
        fastest_in_tier_flag[i] = 0u;
        uint32_t us = results[i][HEADLINE_SIZE_IDX].us_per;
        uint8_t t = ALGOS[i].tier;
        if (us < best[t]) {
            best[t] = us;
            best_idx[t] = i;
        }
    }
    for (uint8_t t = 0; t < NUM_TIERS; t++) {
        if (best_idx[t] != 0xFFu) {
            fastest_in_tier_flag[best_idx[t]] = 1u;
        }
    }
}

/* ---- bench ---------------------------------------------------------- */
static void run_one_at_size(const bench_algo *alg, uint16_t size_bytes,
                            uint32_t actual_iters, bench_result *out_res,
                            uint8_t on_mgba) {
    uint32_t t0, t1, cycles, us_total_alg, us_per, kb_per_s;
    char digest_hex[HASH_MAX_DIGEST * 2u + 1u];
    uint8_t d;

    for (d = 0; d < HASH_MAX_DIGEST; d++) digest[d] = 0u;

    t0 = bench_timer_read();
    for (uint32_t k = 0; k < actual_iters; k++) {
        alg->fn(buffer, size_bytes, digest);
    }
    t1 = bench_timer_read();
    cycles       = t1 - t0;
    us_total_alg = bench_cycles_to_us(cycles);
    us_per       = us_total_alg / actual_iters;
    kb_per_s     = (us_per > 0u)
                   ? ((uint32_t)size_bytes * 1000000u) / (us_per * 1024u)
                   : 0u;

    out_res->us_per   = us_per;
    out_res->kb_per_s = kb_per_s;
    out_res->hash[0]  = digest[0];
    out_res->hash[1]  = digest[1];
    out_res->hash[2]  = digest[2];
    out_res->hash[3]  = digest[3];

    if (on_mgba) {
        format_digest(digest_hex, digest, alg->digest_len);
        mgba_logf(MGBA_LOG_INFO,
                  "%s @ %4u B iters=%lu us/it=%lu KB/s=%lu digest=%s",
                  alg->name, (unsigned)size_bytes,
                  (unsigned long)actual_iters,
                  (unsigned long)us_per, (unsigned long)kb_per_s,
                  digest_hex);
    }
}

/* ---- live status row ------------------------------------------------ */
#define STATUS_Y 152

static void status_clear(void) {
    tte_set_pos(0, STATUS_Y);
    tte_printf("#{P:0,%d}                              ", STATUS_Y);
}
static void status_running(uint8_t cur, uint8_t total, const bench_algo *alg,
                           uint16_t size_bytes) {
    status_clear();
    tte_set_pos(0, STATUS_Y);
    tte_printf("#{P:0,%d}running %2u/%-2u %s @ %4u B",
               STATUS_Y, (unsigned)cur, (unsigned)total,
               alg->name, (unsigned)size_bytes);
}
static void status_total(uint32_t us) {
    uint32_t cs = us / 10000u;
    uint32_t whole = cs / 100u;
    uint32_t frac  = cs % 100u;
    status_clear();
    tte_set_pos(0, STATUS_Y);
    tte_printf("#{P:0,%d}sweep done %lu.%02lus  sort=%s",
               STATUS_Y, (unsigned long)whole, (unsigned long)frac, sort_label());
}

/* ---- render --------------------------------------------------------- */
static void render_row_single(uint8_t row, uint8_t algo_idx) {
    bench_result *r = &results[algo_idx][HEADLINE_SIZE_IDX];
    tte_set_pos(0, row * 8);
    tte_printf("#{P:0,%d}%s %02X%02X%02X%02X %6lu %5lu %c",
               row * 8,
               ALGOS[algo_idx].name,
               r->hash[0], r->hash[1], r->hash[2], r->hash[3],
               (unsigned long)r->us_per,
               (unsigned long)r->kb_per_s,
               fastest_in_tier_flag[algo_idx] ? '*' : ' ');
}

static void render_row_matrix(uint8_t row, uint8_t algo_idx) {
    tte_set_pos(0, row * 8);
    tte_printf("#{P:0,%d}%s %5lu %5lu %5lu %c",
               row * 8,
               ALGOS[algo_idx].name,
               (unsigned long)results[algo_idx][0].kb_per_s,
               (unsigned long)results[algo_idx][1].kb_per_s,
               (unsigned long)results[algo_idx][2].kb_per_s,
               fastest_in_tier_flag[algo_idx] ? '*' : ' ');
}

static void render_page(uint8_t page) {
    uint8_t start = (uint8_t)(page * ROWS_PER_PAGE);
    uint8_t end   = (uint8_t)(start + ROWS_PER_PAGE);
    if (end > NUM_ALGOS) end = NUM_ALGOS;

    tte_erase_screen();

    /* Title row 0 (y=0). */
    tte_set_pos(0, 0);
    tte_printf("#{P:0,0}hash-bench-gba 1KB P%u/%u [%s/%s]",
               (unsigned)(page + 1u), (unsigned)NUM_PAGES,
               sort_label(), mode_label());

    /* Subtitle row 1 (y=8). */
    tte_set_pos(0, 8);
    tte_printf("#{P:0,8}-- %s --", PAGE_SUBTITLE[page]);

    /* Column header row 2 (y=16). */
    tte_set_pos(0, 16);
    if (display_mode == MODE_MATRIX) {
        tte_printf("#{P:0,16}ALGO   64B  256B   1KB *");
    } else {
        tte_printf("#{P:0,16}ALGO    HASH       us  KB/s");
    }

    /* Data rows 3..(3+ROWS_PER_PAGE-1). */
    uint8_t row = 3u;
    for (uint8_t i = start; i < end; i++) {
        uint8_t algo_idx = sort_indices[i];
        if (display_mode == MODE_MATRIX) render_row_matrix(row, algo_idx);
        else                              render_row_single(row, algo_idx);
        row++;
    }

    /* Hint row (y=128). */
    tte_set_pos(0, 128);
    tte_printf("#{P:0,128}A=sort SEL=mode L/R=pg B=rerun");

    /* Re-display total time if available. */
    if (total_us > 0u) status_total(total_us);
}

/* ---- sweep ---------------------------------------------------------- */
static void run_sweep(uint8_t on_mgba) {
    uint32_t sweep_t0, sweep_t1;

    if (on_mgba) {
        mgba_log(MGBA_LOG_INFO, "=== hash-bench-gba sweep ===");
        mgba_log(MGBA_LOG_INFO, "input: 32 algos x 3 sizes (64/256/1024 B)");
    }

    sweep_t0 = bench_timer_read();

    for (uint8_t a = 0; a < NUM_ALGOS; a++) {
        for (uint8_t s = 0; s < BENCH_SIZE_COUNT; s++) {
            uint32_t actual_iters =
                (uint32_t)ALGOS[a].iters * BENCH_SIZE_SCALE[s];
            status_running((uint8_t)(a + 1u), NUM_ALGOS, &ALGOS[a],
                           BENCH_SIZES[s]);
            run_one_at_size(&ALGOS[a], BENCH_SIZES[s], actual_iters,
                            &results[a][s], on_mgba);
        }
    }

    sweep_t1 = bench_timer_read();
    total_us = bench_cycles_to_us(sweep_t1 - sweep_t0);

    compute_tier_flags();
    compute_order();

    if (on_mgba) {
        mgba_logf(MGBA_LOG_INFO, "=== sweep done in %lu.%02lu s ===",
                  (unsigned long)(total_us / 1000000u),
                  (unsigned long)((total_us % 1000000u) / 10000u));
    }
}

/* ---- input ---------------------------------------------------------- */
static void wait_for_action(void) {
    for (;;) {
        VBlankIntrWait();
        key_poll();
        if (key_hit(KEY_B)) return;
        if (key_hit(KEY_A)) {
            sort_mode = (uint8_t)((sort_mode + 1u) % NUM_SORT_MODES);
            compute_order();
            render_page(current_page);
        }
        if (key_hit(KEY_SELECT)) {
            display_mode = (uint8_t)((display_mode + 1u) % 2u);
            render_page(current_page);
        }
        if (NUM_PAGES > 1u) {
            if (key_hit(KEY_LEFT)) {
                current_page = (uint8_t)((current_page + NUM_PAGES - 1u) % NUM_PAGES);
                render_page(current_page);
            } else if (key_hit(KEY_RIGHT)) {
                current_page = (uint8_t)((current_page + 1u) % NUM_PAGES);
                render_page(current_page);
            }
        }
    }
}

int main(void) {
    uint8_t on_mgba;

    irq_init(NULL);
    irq_add(II_VBLANK, NULL);

    REG_DISPCNT = DCNT_MODE0 | DCNT_BG0;
    tte_init_se_default(0, BG_CBB(0) | BG_SBB(31));
    /* CRITICAL: tte_printf is `#define tte_printf iprintf`, which writes
     * through newlib's stdio. Without tte_init_con() redirecting stdio
     * to TTE's tte_write, every tte_printf goes to /dev/null and the
     * screen stays blank. This single missed call was the reason every
     * libtonc-using GBA ROM in this project rendered blank. */
    tte_init_con();

    /* Phosphor-green palette to match totp-gb / totp-gba look-and-feel. */
    pal_bg_mem[0] = PHOS_DARK;
    pal_bg_mem[1] = PHOS_BRIGHT;
    pal_bg_mem[2] = PHOS_MID_LO;
    pal_bg_mem[3] = PHOS_MID_HI;

    on_mgba = mgba_log_init();
    if (on_mgba) mgba_log(MGBA_LOG_INFO, "hash-bench-gba boot");

    bench_timer_init();
    fill_buffer();

    tte_set_pos(0, 0);
    tte_printf("#{P:0,0}hash-bench-gba");
    tte_set_pos(0, 16);
    tte_printf("#{P:0,16}starting sweep...");

    for (;;) {
        run_sweep(on_mgba);
        current_page = 0u;
        render_page(current_page);
        wait_for_action();
    }
}
