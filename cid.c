#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "sim_types.h"
#include "crypto.h"
#include "support.h"
#include "stubs.h"


const EVP_MD *initEvpDigest() {
    return EVP_sha256();
}

const char *getBinEncKey(unsigned int *len) {
    char key_b32[128];
    __int64 a1 = 0;
    bzero(key_b32, sizeof(key_b32));
    get_sign_key(key_b32, 0x21uLL, a1);
    return decode_b32(key_b32, len);
}

int c_hh(void *data, size_t data_len, void *sign, size_t sign_len) {

    const char *bKey;
    unsigned int bKey_len; // ST1C_4
    const EVP_MD *evp_md; // rax
    // rax
    unsigned int bKey_len_alias; // [rsp+18h] [rbp-120h]
    unsigned int digest_len; // [rsp+1Ch] [rbp-11Ch]
    _BYTE buf_to_sign[64]; // [rsp+20h] [rbp-118h]
    _BYTE digest[64]; // [rsp+50h] [rbp-E8h]
    __int64 key_b32[8]; // [rsp+80h] [rbp-B8h]
    _BYTE signature[65]; // [rsp+B0h] [rbp-88h]

    bzero(buf_to_sign, sizeof(buf_to_sign));
    bzero(signature, sizeof(signature));


    bzero(digest, sizeof(digest));
    bzero(key_b32, sizeof(key_b32));

    digest_len = 0;


    bKey = getBinEncKey(&bKey_len);

    evp_md = initEvpDigest();
    HMAC(evp_md, bKey, bKey_len, data, data_len, digest, &digest_len);

    bcvh(digest, 32, signature, 65);

    memcpy(sign, signature, 64);

    return 1;
}

_BYTE locAddr[4];
_BYTE locOtp[20];

int get_totp_token(int ts, unsigned int *res )
{
    __int64 scratch; // rsi
    unsigned int v17; // eax
    unsigned int reshuffle; // ecx
    __int64 ts_shuffled; // [rsp+0h] [rbp-58h]
    unsigned char sign[160]; // [rsp+10h] [rbp-48h]

    const char *bKey;
    unsigned int bKey_len; // ST1C_4
    const EVP_MD *evp_md; // rax
    int sign_len;

    bzero(sign, sizeof(sign));
    ts_shuffled = (__int64)htonl(ts / 30) << 32;

    bKey = getBinEncKey(&bKey_len);

    evp_md = EVP_sha1();
    HMAC(evp_md, bKey, bKey_len, &ts_shuffled, 8, sign, &sign_len);

    v17 = sign[19] & 0xF;
    scratch = sign[v17 + 3];
    reshuffle = ((sign[v17 + 1] << 16) + scratch + (sign[sign[19] & 0xF] << 24) + (sign[v17 + 2] << 8)) & 0x7FFFFFFF;
    *res = reshuffle % 1000000;
    return 1;
}

void gen_otp(time_t ts, char * otp)
{
    unsigned int res;

    get_totp_token(ts, &res);
    snprintf(otp, 7, "%06d", res );

}

void set_loc_data(_BYTE* addr, const char* otp) {
    memcpy(locAddr, addr, 4);
    memcpy(locOtp, otp, 6);
    locOtp[6] = 0;
}

bool cid(unsigned int *local_addr, _BYTE *client_id, char *r_otp) {


    const char *bKey;
    unsigned int bKey_len; // ST1C_4
    const EVP_MD *evp_md; // rax

    _BYTE localid[20];
    _BYTE sign[80];
    size_t sign_len;

    memcpy(localid + 0, locAddr, 4);
    memcpy(localid + 4, locOtp, 6);
    strcpy(r_otp, locOtp);

    bKey = getBinEncKey(&bKey_len);

    evp_md = initEvpDigest();
    HMAC(evp_md, bKey, bKey_len, localid, 10, sign, &sign_len);

    memcpy(client_id, sign, 32);

    return 1;
}

