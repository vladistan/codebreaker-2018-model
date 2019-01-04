#include <strings.h>
#include <limits.h>
#include <stdio.h>
#include "support.h"


unsigned long __readfsqword(int d) {
    return 0x1001;
}

void *qmemcpy(void *dst, const void *src, size_t cnt) {
    char *out = (char *) dst;
    const char *in = (const char *) src;
    while (cnt > 0) {
        *out++ = *in++;
        --cnt;
    }
    return dst;
}

unsigned short __ROL2__(unsigned short n, unsigned int c) {
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.

    c &= mask;
    return (n << c) | (n >> ((-c) & mask));
}

unsigned short __ROR2__(unsigned short n, unsigned int c) {
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);

    c &= mask;
    return (n >> c) | (n << ((-c) & mask));
}