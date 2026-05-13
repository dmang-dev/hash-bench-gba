/*
 * mGBA log wrapper — identical to the totp-gba implementation, kept
 * standalone so this project doesn't depend on the sibling repo.
 *
 * Reference: https://mgba.io/2017/04/30/emulator-feature-set/
 */
#include "mgba_log.h"
#include <stdio.h>
#include <stdarg.h>

#define REG_MGBA_DEBUG_ENABLE  ((volatile uint16_t *)0x04FFF780)
#define REG_MGBA_DEBUG_FLAGS   ((volatile uint16_t *)0x04FFF700)
#define MGBA_DEBUG_STRING      ((volatile char *)    0x04FFF600)

#define MGBA_DEBUG_BUFFER_SIZE 256u

uint8_t mgba_log_init(void) {
    *REG_MGBA_DEBUG_ENABLE = 0xC0DEu;
    return (*REG_MGBA_DEBUG_ENABLE == 0x1DEAu) ? 1u : 0u;
}

void mgba_log(uint8_t level, const char *msg) {
    uint16_t i;
    for (i = 0; i < MGBA_DEBUG_BUFFER_SIZE && msg[i] != '\0'; i++) {
        MGBA_DEBUG_STRING[i] = msg[i];
    }
    if (i < MGBA_DEBUG_BUFFER_SIZE) {
        MGBA_DEBUG_STRING[i] = '\0';
    }
    *REG_MGBA_DEBUG_FLAGS = (uint16_t)(level | 0x100u);
}

void mgba_logf(uint8_t level, const char *fmt, ...) {
    char buf[MGBA_DEBUG_BUFFER_SIZE];
    va_list ap;
    va_start(ap, fmt);
    vsniprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    mgba_log(level, buf);
}
