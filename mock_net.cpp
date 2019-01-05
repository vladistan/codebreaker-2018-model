extern "C" {
#include "mock_net.h"
#include "mock_data.h"
}

#include <CppUTestExt/MockSupport.h>


static int sndCalls = 0;

_BYTE mock_snd_store[3][STD_PACKET_SIZE];

ssize_t mock_send(int socket, const void *buffer, size_t length, int flags) {

    mock().actualCall("send");
    if(length == sizeof(mock_snd_store[0]) && sndCalls < 3 ) {
        memcpy(mock_snd_store[sndCalls], buffer, length);
        sndCalls++;
    }
    return length;
}



void mock_recv_init(int state){
    sndCalls = 0;
}
