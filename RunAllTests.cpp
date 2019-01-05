#include <string.h>

#include "RunAllTests.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTestExt/MockSupport.h>
#include <resolv.h>


extern "C" {
#include "support.h"
#include "stubs.h"
#include "sim_types.h"
#include "mock_data.h"
#include "client.h"
#include "crypto.h"
}




TEST_GROUP(Sizes) {
    void setup() {}

    void teardown() { mock().clear(); }
};

TEST(Sizes, Byte) {
    LONGS_EQUAL(sizeof(_BYTE), 1);
}

TEST(Sizes, Word) {
    LONGS_EQUAL(sizeof(_WORD), 2);
}

TEST(Sizes, Dword) {
    LONGS_EQUAL(sizeof(_DWORD), 4);
}

TEST(Sizes, QWord) {
    LONGS_EQUAL(sizeof(_QWORD), 8);
}

TEST(Sizes, Int64) {
    LONGS_EQUAL(sizeof(__int64), 8);
}

TEST(Sizes, Int16) {
    LONGS_EQUAL(sizeof(__int16), 2);
}

TEST(Sizes, SockAddrIn) {
    LONGS_EQUAL(sizeof(sockaddr_in), 0x10);
}

TEST(Sizes, Bundle) {
    LONGS_EQUAL(sizeof(struct bundle), 0x790);
}

TEST(Sizes, CliHelloPkt) {
    LONGS_EQUAL(sizeof(struct cliHelloPkt), 0x300);
}

TEST(Sizes, CliPkt) {
    LONGS_EQUAL(sizeof(union CliPkt), 0x300);
}

TEST(Sizes, CliHelloPktOff1) {
    LONGS_EQUAL(offsetof(cliHelloPkt, victim_ip_hx), 0x2);
}

TEST(Sizes, CliHelloPktOff2) {
    LONGS_EQUAL(offsetof(cliHelloPkt, enc_k), 0x50);
}

TEST(Sizes, CliHelloPktOff3) {
    LONGS_EQUAL(offsetof(cliHelloPkt, otp), 0x4A);
}


TEST_GROUP(Rot) {

    void setup() {}

    void teardown() { mock().clear(); }

};

TEST(Rot, Right) {
    LONGS_EQUAL(0x4123, __ROR2__(0x1234, 4))
}

TEST(Rot, Left) {
    LONGS_EQUAL(0x2341, __ROL2__(0x1234, 4))
}

TEST_GROUP(Misc) {
    void setup() {}

    void teardown() { mock().clear(); }
};

TEST(Misc, ReadQsWord) {
    LONGS_EQUAL(0x1001, __readfsqword(0x1234))
}

TEST(Misc, QMemCpy) {
    const char *hll = "Hello World";
    char msg[40];
    qmemcpy(msg, hll, strlen(hll) + 1);
    char *n = static_cast<char *>(qmemcpy(msg, msg + 6, 5));
    STRCMP_EQUAL(n, "World World");
    STRCMP_EQUAL(msg, "World World");
}

TEST(Misc, DispatchServer) {
    bnd bnd1;
    bool n = dispatch_server_command(&bnd1, (char *) "Hello");
    LONGS_EQUAL(0x1, n)
}

TEST(Misc, Vhh) {
    bnd bnd1;
    bool n = v_hh((void *) "Hello", 12, &bnd1, 45);
    LONGS_EQUAL(0x1, n)
}

TEST(Misc, Chh) {
    bnd bnd1;
    bool n = c_hh(&bnd1, 592, &bnd1, 64);
    LONGS_EQUAL(0x1, n)
}

TEST(Misc, Cid) {
    unsigned int localip = 0x12345678;
    _BYTE client_id_maybe[32];
    char otp[6];
    bool n = cid(&localip, client_id_maybe, otp);
    LONGS_EQUAL(0x1, n)
}

TEST(Misc, Bcvh) {
    _BYTE bnd1[40];
    bool n = bcvh((_BYTE *) bnd1, 1, bnd1, 3);
    LONGS_EQUAL(0x1, n)
}

TEST_GROUP(Encoders) {
    void setup() {}

    void teardown() { mock().clear(); }
};

TEST(Encoders, EncSmallByteVal) {
    _BYTE src[] = {0x2};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "02", 2);
}

TEST(Encoders, EncByteValeMoreThanA) {
    _BYTE src[] = {0xC};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "0c", 2);
}

TEST(Encoders, EncByteValueEdgeCase) {
    _BYTE src[] = {0xA};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "0a", 2);
}

TEST(Encoders, EncByteValueTwoDigits) {
    _BYTE src[] = {0x10};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "10", 2);
}

TEST(Encoders, EncByteValueTwoDigitsEdge) {
    _BYTE src[] = {0xff};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "ff", 2);
}

TEST(Encoders, EncLonger) {
    _BYTE src[] = {0xf3, 0x10, 0x94, 0x84, 0x11, 0x00, 0x01, 0x55, 0xea, 0xa0};
    _BYTE dst[30];


    bzero(dst, sizeof(dst));

    bcvh(src, 10, dst, 21);

    MEMCMP_EQUAL(dst, "f310948411000155eaa0", 21);

}

TEST(Encoders, EncIP) {

    _BYTE res[9] = {0x30, 0x61, 0x32, 0x66, 0x37, 0x32, 0x31, 0x36, 0};
    _BYTE src[4] = {10, 47, 114, 22};
    _BYTE dst[9];

    memset(dst, 0x34, 9);

    bcvh(src, 4, dst, 9);

    MEMCMP_EQUAL(dst, res, 9);

}

TEST(Encoders, EncByteValueTwoDigitsEdgeM1) {
    _BYTE src[] = {0xfe};
    _BYTE dst[4];

    bzero(dst, sizeof(src));
    encByte(src[0], dst);

    MEMCMP_EQUAL(dst, "fe", 2);
}

TEST_GROUP(Crypto) {
    void setup() {
    }

    void teardown() {}
};


TEST(Crypto, get_key) {

    char key[128];
    int a3;
    const char *enc_key = "CAYPFE6MG2DJT4EB5RIZLIAYFJAUGL3L";

    bzero(key, sizeof(key));
    get_sign_key(key, sizeof(key), a3);

    STRCMP_EQUAL(enc_key, (const char *) key);

}

TEST(Crypto, EvpDigest) {

    const EVP_MD *evp;
    evp = initEvpDigest();

}

TEST(Crypto, BinEncKey) {

    const char *key;
    _BYTE expKey[20] = {
            0x10, 0x30, 0xF2, 0x93, 0xCC, 0x36, 0x86, 0x99,
            0xF0, 0x81, 0xEC, 0x51, 0x95, 0xA0, 0x18, 0x2A,
            0x41, 0x43, 0x2F, 0x6B
    };
    unsigned int bkLen = 0;

    key = getBinEncKey(&bkLen);

    LONGS_EQUAL(bkLen, 21);
    MEMCMP_EQUAL(expKey, key, 20);

}

TEST_GROUP(B32codecs) {
    void setup() {}

    void teardown() { mock().clear(); }
};

TEST(B32codecs, simpleDec) {
    const char *src = "JBSWY3DPEBUG65Z7";
    const char *exp = "Hello how?";
    char dst[1024];

    b32dec(src, dst);

    STRCMP_EQUAL(exp, dst);

}

TEST(B32codecs, properDec) {

    const char *src = "JBSWY3DPEBUG65Z7";
    const char *exp = "Hello how?";
    int len = 0;
    const char *rv = decode_b32(src, &len);

    LONGS_EQUAL(11, len);
    STRCMP_EQUAL(exp, rv);
}
TEST_GROUP(PartialFunctions) {
    void setup() {
    //    const char *otp = "197548";
    //    _BYTE src[4] = {10, 47, 114, 22};
    //    set_loc_data(src, otp);

    }

    void teardown() { mock().clear(); }
};

TEST(PartialFunctions, check_send_srv_ping) {

    __int64 *send_ptr;
    socklen_t local_addr_len;
    __int64 client_id_maybe_hx[8];
    _WORD loc_addr_ln_hx;
    __int64 sign[8];
    unsigned int saddr = 0x01020304;
    bnd bundle;
    union CliPkt payLoad;

    char otp[7];

    cid(&saddr, bundle.victim_id, otp);

    prep_ping_pkt(&loc_addr_ln_hx, client_id_maybe_hx,
                  sign, &local_addr_len, &bundle, &payLoad);


    MEMCMP_EQUAL(snd_pkt_2, bundle.send_pkt_sign, STD_PACKET_SIZE);


}

TEST(PartialFunctions, check_clean_buffers_is_right) {

    bnd bundle;

    memset(&bundle, 0x9, sizeof(bnd));

    cleanBuffers(&bundle);

    LONGS_EQUAL(bundle.victim_ip, 0x9090909);
    LONGS_EQUAL(bundle.sock, 0x9090909);
    LONGS_EQUAL(bundle.state, 0x9090909);

    LONGS_EQUAL(bundle.rcv_buf[0], 0);
    LONGS_EQUAL(bundle.rcv_buf[765], 0);
    LONGS_EQUAL(bundle.send_pkt_sign[0], 0);
    LONGS_EQUAL(bundle.rcvd, 0);
    LONGS_EQUAL(bundle.sent, 0);

}

TEST(PartialFunctions, check_form_first_pack_to_srv_correctly) {

    socklen_t local_addr_len;

    bnd bundle;
    _WORD loc_addr_ln_hx;
    char otp[12];
    _QWORD victim_ip_hx;
    char zero_pad3;
    __int64 client_id_maybe_hx[8];
    char zero_pad4;
    __int64 sign[8];
    char zero_pad5;
    union CliPkt payLoad;
    _BYTE pkt_prep[STD_PACKET_SIZE];

    mock().expectOneCall("send");

    memset(sign, 0x99, sizeof(sign));

    _BYTE victim_ip[4] = {10, 47, 114, 22};
    memcpy(&bundle.victim_ip, victim_ip, 4);


    send_hello_pkt(
            &loc_addr_ln_hx, otp,
            &victim_ip_hx, client_id_maybe_hx,
            sign, &local_addr_len,
            &bundle, &payLoad, pkt_prep);


    mock().checkExpectations();

    MEMCMP_EQUAL(expected_first_sent_pack, bundle.send_pkt_sign, STD_PACKET_SIZE);


}

TEST(PartialFunctions, check_rcv_server_hello_is_good) {
    char *rcv_ptr;
    _QWORD rcv_len_2;
    int rcvd;
    bnd bundle;

    mock_recv_init(MOCK_RCV_STATE_RCV_HELLO);
    mock().expectOneCall("recv");

    rcv_hello_rsp(rcv_ptr, rcv_len_2, rcvd, &bundle);

    mock().checkExpectations();

    LONGS_EQUAL(bundle.state, STATE_SRV_PING);
    LONGS_EQUAL(bundle.rcvd, 64LL);
    LONGS_EQUAL(bundle.sent, 656);

}

TEST(PartialFunctions, make_srv_sock_addr) {

    sockaddr_in addr;
    make_srv_sock_addr("172.17.39.217", 80, (sockaddr *) &addr);
    unsigned char b_addr[] = {172, 17, 39, 217};

    LONGS_EQUAL(addr.sin_family, AF_INET);
    LONGS_EQUAL(addr.sin_len, 16);
    LONGS_EQUAL(addr.sin_port, 0x5000);
    MEMCMP_EQUAL(&addr.sin_addr.s_addr, b_addr, 4);
}

TEST(PartialFunctions, bundle_init_works) {

    sockaddr_in addr;
    bnd bundle;
    unsigned char b_addr[] = {172, 17, 39, 217};

    mock().expectOneCall("connect");

    client_init("172.17.39.217", 9999, (sockaddr *) &addr, &bundle);

    mock().checkExpectations();

    LONGS_EQUAL(addr.sin_family, AF_INET);
    LONGS_EQUAL(addr.sin_len, 16);
    LONGS_EQUAL(addr.sin_port, 0x0f27);
    MEMCMP_EQUAL(&addr.sin_addr.s_addr, b_addr, 4);

    CHECK(bundle.sock > 0);
    LONGS_EQUAL(bundle.state, STATE_INIT);
    CHECK(bundle.state > 0);

}

TEST(PartialFunctions, check_can_get_own_addr) {

    /* Setup */

    bnd bundle;
    sockaddr_in addr;
    socklen_t addr_len;

    bzero(&bundle, sizeof(bnd));


    make_srv_sock_addr("216.58.216.3", 9999, (sockaddr *) &addr);

    mock().expectOneCall("connect");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    bundle.sock = sock;
    int rv = connect(sock, (sockaddr *) &addr, sizeof(addr));

    CHECK(rv >= 0)

    /* Test */

    get_my_addr(&addr_len, &bundle);

    /* Verify */

    LONGS_EQUAL(addr_len, 0x10);
    LONGS_EQUAL(bundle.loc_addr.sin_family, 2);
    LONGS_EQUAL(bundle.loc_addr.sin_port, 0xeaa8);
    LONGS_EQUAL(bundle.victim_ip, 0x16722f0a);
    LONGS_EQUAL(bundle.loc_addr.sin_addr.s_addr, 0x16722f0a);


}


TEST_GROUP(Transmit) {
    void setup() {}

    void teardown() { mock().clear(); }
};

TEST(Transmit, SendIsCalled) {

    bnd bundle;

    memset(bundle.send_pkt_pload, 0, sizeof(bundle.send_pkt_pload));
    strcpy((char *) bundle.send_pkt_pload, "Hello There");

    mock().expectOneCall("send");
    transmit(&bundle);
    mock().checkExpectations();

}


int main(int ac, char **av) {
    return CommandLineTestRunner::RunAllTests(ac, av);
}


