#include "client.h"
#include "mock_net.h"

unsigned int transmit(struct bundle *bnd)
{
    unsigned int sent; // rax
    char *v2; // rbp
    int v3; // eax

    sent = 0LL;
    v2 = (char *)bnd->send_pkt_sign;
    bnd->sent = 0LL;
    do
    {
        v3 = send(bnd->sock, v2, 768 - sent, 0);
        if ( v3 < 0 )
            return 1;
        v2 += v3;
        sent = bnd->sent + v3;
        bnd->sent = sent;
    }
    while ( sent <= 0x2FF );
    return 0;
}
