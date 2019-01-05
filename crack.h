#ifndef _CRACK_INCLUDED_H
#define _CRACK_INCLUDED_H

#include "sim_types.h"

int cid_matches(const char *CIDs[], int cid_count, const char *cid);
void gen_otp_val(char otpBuf[], int val);
void gen_display_res(char *buf, unsigned char *src);
int cid_crack_attempt(const char *CIDs[5], int cid_count, _BYTE src[4], int otp);
int cid_crack(const char *pString[5], int cid_count, _BYTE oct3_low, _BYTE oct3_hi, _BYTE oct4_low, _BYTE oct4_hi, int otplow, int otphi);
int crk_slice_start(int slice);
int crk_slice_end(int slice);



#endif
