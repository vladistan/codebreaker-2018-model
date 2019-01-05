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
