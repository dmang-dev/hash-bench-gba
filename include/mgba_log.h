/*
 * mGBA debug-log register wrapper. Drop-in copy of the totp-gba helper —
 * exposes the 256-byte string buffer at 0x04FFF600 plus the enable /
 * flush registers. Use mgba_log_init() once at boot; if it returns
 * non-zero, mgba_log / mgba_logf can be called safely.
 */
#ifndef MGBA_LOG_H
#define MGBA_LOG_H

#include <stdint.h>

#define MGBA_LOG_FATAL 0u
#define MGBA_LOG_ERROR 1u
#define MGBA_LOG_WARN  2u
#define MGBA_LOG_INFO  3u
#define MGBA_LOG_DEBUG 4u

uint8_t mgba_log_init(void);
void    mgba_log(uint8_t level, const char *msg);
void    mgba_logf(uint8_t level, const char *fmt, ...);

#endif
