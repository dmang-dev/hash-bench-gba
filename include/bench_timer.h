/*
 * Cascaded hardware timer for cycle-accurate benchmark timing.
 *
 * TM0 counts every system clock (16.78 MHz on GBA), TM1 counts TM0
 * overflows. Together they form a 32-bit counter at full bus rate that
 * wraps every ~256 seconds — plenty for any single hash run.
 *
 * Usage:
 *   bench_timer_init();   once at boot
 *   t0 = bench_timer_read();
 *   ...work...
 *   t1 = bench_timer_read();
 *   cycles = t1 - t0;     uint32_t subtraction is wrap-safe
 */
#ifndef BENCH_TIMER_H
#define BENCH_TIMER_H

#include <stdint.h>

#define BENCH_TIMER_HZ 16780000u   /* ARM7TDMI bus clock */

void     bench_timer_init(void);
uint32_t bench_timer_read(void);

/* Convert raw cycle delta -> microseconds (rounded). */
uint32_t bench_cycles_to_us(uint32_t cycles);

#endif
