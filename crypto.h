#ifndef _CRYPTO_H_INCLUDED
#define _CRYPTO_H_INCLUDED

#include <openssl/ossl_typ.h>
#include "sim_types.h"

__int64 get_sign_key(char *addr, __int64 len, __int64 a3);

void b32dec(const char *src, char dst[1024]);
const char *decode_b32(const char *src, int *pInt);
const EVP_MD * initEvpDigest() ;
const char *getBinEncKey(unsigned int *len);


#endif


