#include <limits.h>
#include <netinet/in.h>

#ifndef SIM_TYPES
#define SIM_TYPES

typedef unsigned long int __uint64;
typedef long int __int64;
typedef long __int32;
typedef short __int16;

typedef unsigned char _BYTE;
typedef unsigned short _WORD;
typedef unsigned int _DWORD;
typedef unsigned long long _QWORD;

typedef struct { _QWORD a; _QWORD b; } _OWORD;


typedef unsigned short  uint16;
#define LOBYTE(x)   (*((_BYTE*)&(x)))   // low byte
#define LOWORD(x)   (*((_WORD*)&(x)))   // low word
#define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword
#define HIBYTE(x)   (*((_BYTE*)&(x)+1))
#define HIWORD(x)   (*((_WORD*)&(x)+1))
#define HIDWORD(x)  (*((_DWORD*)&(x)+1))
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))

#define STD_PACKET_SIZE  768

#endif // SIM_TYPES
