

#include "sim_types.h"

#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED 1



struct bundle {
    _BYTE unknown[800];
    _QWORD send_pkt_sign[8];
    _BYTE send_pkt_pload[704];
    _QWORD unknown2;
    _QWORD sent;
    int sock;
    _BYTE field_680x[332];
    struct sockaddr_in loc_addr;
};


struct __attribute__((packed)) cliHelloPkt {
    _WORD local_addr;
    _QWORD victim_ip_hx;
    _QWORD client_id_maybe[8];
    _BYTE otp[6];
    _BYTE enc_k[512];
    _QWORD field_248;
    _BYTE pad_2[64];
    _BYTE field_288[64];
    _BYTE field_2D8[40];
};


union CliPkt {
    struct cliHelloPkt hello;
    _BYTE raw[768];
};


typedef struct bundle bnd;


unsigned int transmit(bnd *bundle);
#endif
