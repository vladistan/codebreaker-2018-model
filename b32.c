#include <string.h>
#include <stdlib.h>
#include "crypto.h"

static unsigned char shift_right(unsigned char byte, char offset) {
    if (offset > 0)
        return byte >> offset;
    else
        return byte << -offset;
}

static unsigned char shift_left(unsigned char byte, char offset) {
    return shift_right(byte, -offset);
}

static int get_offset(int block) {
    return (8 - 5 - (5 * block) % 8);
}

static int get_octet(int block) {
    return (block * 5) / 8;
}

static int decode_char(unsigned char c) {
    char retval = -1;

    if (c >= 'A' && c <= 'Z')
        retval = c - 'A';
    if (c >= '2' && c <= '7')
        retval = c - '2' + 26;

    return retval;
}

static int decode_sequence(const unsigned char *coded, unsigned char *plain) {

    plain[0] = 0;
    for (int block = 0; block < 8; block++) {
        int offset = get_offset(block);
        int octet = get_octet(block);

        int c = decode_char(coded[block]);
        if (c < 0)  // invalid char, stop here
            return octet;

        plain[octet] |= shift_left(c, offset);
        if (offset < 0) {  // does this block overflows to next octet?
            plain[octet + 1] = shift_left(c, 8 + offset);
        }
    }
    return 5;
}

size_t base32_decode(const unsigned char *coded, unsigned char *plain) {
    size_t written = 0;
    for (size_t i = 0, j = 0;; i += 8, j += 5) {
        int n = decode_sequence(&coded[i], &plain[j]);
        written += n;
        if (n < 5)
            return written;
    }
}

void b32dec(const char *src, char dst[1024]) {

    base32_decode(src, dst);

}

const char *decode_b32(const char *src, int *pInt) {

    int ln = strlen(src);
    ln = 5 * ((ln + 7) >> 3) + 1;

    char *dst = malloc(ln + 8);
    *pInt = ln;

    base32_decode(src, dst);

    return dst;
}

