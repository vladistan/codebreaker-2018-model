#include <stdio.h>
#include "mock_data.h"
#include "client.h"
#include "stubs.h"


void encHexDigit(_BYTE bEnc, _BYTE *dst);

bool v_hh(void *string, long long int i, void *buffer, long long int i1) {

    if (i == 656LL && i1 == 64) {
        return 0;
    } else if (i == 42LL && i1 == 64) {
        return 0;
    }
    return 1;
}


void encByte(_BYTE bEnc, _BYTE *dst) {
    encHexDigit((bEnc & 0xf0) >> 4, dst);
    dst++;
    encHexDigit(bEnc & 0xf, dst);
}

void encHexDigit(_BYTE bEnc, _BYTE *dst) {
    if (bEnc < 0xA) {
        *dst = 0x30 + bEnc;
    } else {
        *dst = 0x60 + bEnc - 9;
    }
}

bool bcvh(_BYTE *src, long long int src_len, _BYTE *dst, long long int dst_len) {

    if (src_len * 2 + 1 != dst_len) {
        printf("AIEEE: Dst/Src len mismatch.  Src %lli Dst %lli ", src_len, dst_len);
        return 0;
    }

    for (int i = 0; i < src_len; i++) {
        encByte( src[i], &dst[i*2]);
    }
    dst[dst_len-1] = 0;
    return 1;
}

bool enc_ki(void *data, long long int len) {

    if (len != sizeof(loc_enc_ki)) {
        puts("AIIEEE:  Local EnC Key is Diff Len than asked of us");
        return 0;
    }

    memcpy(data, loc_enc_ki, len);
    return 1;
}

bool dispatch_server_command(void *ptr, char *alias_3) {
    return 1;
}

