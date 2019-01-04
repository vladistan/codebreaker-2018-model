#ifndef _SUPPORT_H_INCL_
#define _SUPPORT_H_INCL_

unsigned long __readfsqword(int d);

void *qmemcpy(void *dst, const void *src, size_t cnt);

unsigned short __ROL2__(unsigned short n, unsigned int c);

unsigned short __ROR2__(unsigned short n, unsigned int c);

#endif