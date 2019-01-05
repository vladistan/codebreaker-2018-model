#include <string.h>
#include <stdio.h>
#include <time.h>
#include "crack.h"
#include "stubs.h"


int cid_matches(const char *ids[], int cid_count, const char *cid) {

    for (int i = 0; i < cid_count; i++) {
        if (strcmp(ids[i], cid) == 0)
            return 1;
    }
    return 0;
}


void gen_otp_val(char otpBuf[], int val) {
    snprintf(otpBuf, 7, "%d", val);
}

void gen_display_res(char *buf, unsigned char *src) {
    snprintf(buf, 60, "%d.%d.%d.%d", src[0], src[1], src[2], src[3]);
}

int cid_crack_attempt(const char *cid_ids[5], int cid_count, _BYTE src[4], int n_otp) {

    unsigned int localip = 0x12345678;
    _BYTE client_id_b[128];
    char client_id_hx[128];
    char otp[9];

    bzero(client_id_b, sizeof(client_id_b));
    bzero(client_id_hx, sizeof(client_id_hx));
    bzero(otp, sizeof(otp));

    gen_otp_val(otp, n_otp);
    set_loc_data(src, otp);

    int n = cid(&localip, client_id_b, otp);
    bcvh(client_id_b, 32, (_BYTE *) client_id_hx, 65);


    int rv = cid_matches(cid_ids, cid_count, client_id_hx);
    if (rv ) {
      puts(client_id_hx);
    }
    return rv;
}

int crk_slice_start(int slice) {
    return 32 * slice;
}


int crk_slice_end(int slice) {
    return 32 * slice + 31;
}


int cid_crack(const char *CIDs[5], int cid_count,
              _BYTE oct3_low, _BYTE oct3_hi,
              _BYTE oct4_low, _BYTE oct4_hi,
              int otplow, int otphi) {

    _BYTE src[4] = {10, 47, 0, 0};
    time_t start = time(NULL);

    int rv = 0;

    printf("NET: %d.%d.%d.%d --> %d.%d.%d.%d\n",
              src[0], src[1], oct3_low, oct4_low ,
              src[0], src[1], oct3_hi, oct4_hi
            );
    printf("OTP %06d --> %06d \n", otplow, otphi );

    for (int otp = otplow; otp <= otphi; otp++) {
        if (otp % 50000 == 1 && otp > 1) {
            time_t elapsed = time(NULL) - start;
            printf("Try: %06d %.2f/sec\n", otp, (otp * 1.0) / (elapsed * 1.0));
        }
        for (_BYTE o3 = oct3_low; o3 <= oct3_hi; o3++) {
            for (_BYTE o4 = oct4_low; o4 <= oct4_hi; o4++) {
                src[2] = o3;
                src[3] = o4;

                if (cid_crack_attempt(CIDs, cid_count, src, otp)) {
                    char found[20];
                    gen_display_res(found, src);
                    printf("\nFOUND: %s\n", found);
                    rv = 1;
                }

                if (o4 == 255) { break; }
            }
            if (o3 == 255) { break; }
        }
    }

    return rv;

}
