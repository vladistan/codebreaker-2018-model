extern "C" {
#include "mock_net.h"
#include "mock_data.h"
}

#include <CppUTestExt/MockSupport.h>


static int rcvState = 0;
static int rcvCalls = 0;
static int sndCalls = 0;

_BYTE mock_snd_store[3][STD_PACKET_SIZE];

ssize_t mock_send(int socket, const void *buffer, size_t length, int flags) {

    mock().actualCall("send");
    if(rcvState == MOCK_RCV_STATE_RCV_PONG && length == sizeof(mock_snd_store[0]) && sndCalls < 3 ) {
        memcpy(mock_snd_store[sndCalls], buffer, length);
        sndCalls++;
    }
    return length;
}

int mock_connect(int socket, struct sockaddr * addr, int len ) {


    struct sockaddr_in *ad = (sockaddr_in*)addr;

    if(ad->sin_port != htons(9999)) return -1;

    mock().actualCall("connect");

    return 0;

}


void mock_recv_init(int state){
    rcvState = state;
    rcvCalls = 0;
    sndCalls = 0;
}

int mock_recv(int socket, char * buf, int len, int flags) {

    if ( rcvState == MOCK_RCV_STATE_RCV_HELLO && len == sizeof(rcv_pkt_2) && rcvCalls == 0)
    {
        memcpy(buf, rcv_pkt_2, len);
        mock().actualCall("recv");
        rcvCalls++;
        return len;
    } else if ( rcvState == MOCK_RCV_STATE_RCV_PONG && len == sizeof(rcv_pkt_3) && rcvCalls == 0) {
        memcpy(buf, rcv_pkt_3, len);
        mock().actualCall("recv");
        rcvCalls++;
        return len;
    }


    return -1;
};



int  mock_getsockname(int, struct sockaddr * addr, socklen_t *len) {

    *len = 16;
    sockaddr_in * ad = (sockaddr_in *)(addr);

    ad->sin_family = AF_INET;
    ad->sin_port = htons(43242);
    ad->sin_addr.s_addr = 0x16722f0a;
    ad->sin_len = 16;
    bzero(ad->sin_zero, sizeof(*ad->sin_zero));

    *len = 16;


    return 0;
}



