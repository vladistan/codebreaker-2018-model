#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mock_net.h"

#include "sim_types.h"

#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED 1

typedef enum {
    STATE_INIT = 1, STATE_CLI_HELLO = 2, STATE_SRV_PING = 3, STATE_CLI_PONG = 4, STATE_CLEANUP = 5
} cli_state;



struct bundle {
    int state;
    int field_4[5];
    unsigned int victim_ip;
    _DWORD field_1C;
    _BYTE rcv_buf[768];
    _QWORD send_pkt_sign[8];
    _BYTE send_pkt_pload[704];
    _QWORD rcvd;
    _QWORD sent;
    int sock;
    _BYTE victim_id[32];
    int pad[10];
    int done;
    _BYTE field_680x[256];
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

struct __attribute__((packed)) cliPingPkt {
    _WORD local_addr;
    _QWORD client_id_maybe[8];
};

union CliPkt {
    struct cliHelloPkt hello;
    struct cliPingPkt ping;
    _BYTE raw[768];
};


typedef struct bundle bnd;


unsigned int transmit(bnd *bundle);
void make_srv_sock_addr(const char *cp, __int16 a2, struct sockaddr *addr);

void get_my_addr(socklen_t *local_addr_len, struct bundle *bnd);

void client_init(const char *cp, __int16 a2, struct sockaddr *addr, struct bundle *bnd);

void send_hello_pkt(_WORD *loc_addr_ln_hx, char *otp, _QWORD *victim_ip_hx,
                    const __int64 *victim_id_hx, const __int64 *sign, socklen_t *pkt_type,
                    struct bundle *bnd, union CliPkt *payLoad, _BYTE *pkt_prep);

void rcv_hello_rsp(char *rcv_ptr, _QWORD rcv_len_2, int rcvd, struct bundle *bnd);

void prep_ping_pkt(_WORD *loc_addr_ln_hx, const __int64 *victim_id_hx, const __int64 *sign,
                   socklen_t *local_addr_len, struct bundle *bnd, union CliPkt *payLoad);


void cleanBuffers(struct bundle *bnd);

int do_ping_pong(_WORD *loc_addr_ln_hx, const __int64 *client_id_maybe_hx, const __int64 *sign, socklen_t *local_addr_len,
                 struct bundle *bnd, union CliPkt *payLoad);

#endif
