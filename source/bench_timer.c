/*
 * Cascaded TM0+TM1 timer — TM0 ticks every bus cycle (prescaler 1),
 * TM1 cascade-counts TM0 overflows. Combined into a 32-bit free-running
 * counter at 16.78 MHz.
 *
 * Read pattern: re-read the high half after the low half and retry on
 * mismatch, since TM0 could overflow into TM1 between the two MMIO
 * loads and yield a torn count.
 */
#include "bench_timer.h"
#include <tonc.h>

void bench_timer_init(void) {
    /* Reset and configure both timers. TM0 free-runs at 16.78 MHz,
     * TM1 increments only when TM0 overflows. */
    REG_TM0CNT_H = 0;
    REG_TM1CNT_H = 0;
    REG_TM0CNT_L = 0;
    REG_TM1CNT_L = 0;
    REG_TM1CNT_H = TM_ENABLE | TM_CASCADE;
    REG_TM0CNT_H = TM_ENABLE;
}

uint32_t bench_timer_read(void) {
    uint16_t hi1, hi2, lo;
    do {
        hi1 = REG_TM1CNT_L;
        lo  = REG_TM0CNT_L;
        hi2 = REG_TM1CNT_L;
    } while (hi1 != hi2);
    return ((uint32_t)hi1 << 16u) | lo;
}

uint32_t bench_cycles_to_us(uint32_t cycles) {
    /* (cycles * 1e6 + Hz/2) / Hz, but cycles * 1e6 overflows uint32_t
     * for ~4300 cycles (≈ 0.25 ms). Use 64-bit intermediate. */
    uint64_t num = (uint64_t)cycles * 1000000ULL + (BENCH_TIMER_HZ / 2u);
    return (uint32_t)(num / BENCH_TIMER_HZ);
}
