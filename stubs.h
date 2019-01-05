#ifndef _STUBS_H_
#define _STUBS_H_

#include <stdbool.h>
#include "sim_types.h"

bool v_hh(void *string, long long int i, void *buffer, long long int i1);
int c_hh(void *block, size_t len, void *data, size_t d_len);
bool cid(unsigned int *local_addr, _BYTE *client_id, char *otp_str);
bool bcvh(_BYTE *src, long long int sLen, _BYTE *dst, long long int dLen);
bool enc_ki(void *, long long int len);
bool dispatch_server_command(void *ptr, char *alias_3);
void set_loc_data(_BYTE *addr, const char *otp);

void encByte(_BYTE src, _BYTE *dst);

#endif
