

#include "sim_types.h"

#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED 1

struct __attribute__((packed)) cliHelloPkt {
    _WORD local_addr;
    _QWORD victim_ip_hx;
    _QWORD client_id[8];
    _BYTE otp[6];
    _BYTE enc_k[512];
    _QWORD pad[22];
};


union CliPkt {
    struct cliHelloPkt hello;
    _BYTE raw[768];
};
#endif
