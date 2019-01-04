

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTestExt/MockSupport.h>


extern "C" {
#include "support.h"
#include "sim_types.h"
#include "client.h"
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


TEST(Sizes, CliHelloPkt) {
    LONGS_EQUAL(sizeof(struct cliHelloPkt), 0x300);
}

TEST(Sizes, CliPkt) {
    LONGS_EQUAL(sizeof(union CliPkt), 0x300);
}


TEST(Sizes, CliHelloPktOff2) {
    LONGS_EQUAL(offsetof(cliHelloPkt, enc_k), 0x50);
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

int main(int ac, char **av) {
    return CommandLineTestRunner::RunAllTests(ac, av);
}
