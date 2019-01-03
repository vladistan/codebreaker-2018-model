cmake_minimum_required(VERSION 3.3)
project(Replica)


enable_language(C)
enable_language(CXX)


include_directories(BEFORE /usr/local/Cellar/openssl/1.0.2p/include)


find_library(OPENSSL_LIB
                ssl
                PATHS /usr/lib /usr/local/Cellar/openssl/1.0.2p/lib
                NO_DEFAULT_PATH)
find_library(CRYPTO_LIB
                crypto
                PATHS /usr/lib /usr/local/Cellar/openssl/1.0.2p/lib
                NO_DEFAULT_PATH)

find_library(CPPUTEST_LIB CppUTest $ENV{CRYPTO_LIB_PATH})
find_library(CPPUTEST_EXT_LIB CppUTestExt $ENV{CRYPTO_LIB_PATH})
find_library(PROFILE_LIB profile_rt $ENV{CRYPTO_LIB_PATH})

message(${OPENSSL_LIB})

set(CLI_SOURCE_FILES client.c transmit.c mock_data.c stubs.c support.c crypto.c b32.c cid.c crack.c)
set(MOCK_SOURCE_FILES mock_net.cpp)

set(REPLICA_SOURCE_FILES replica.c )

add_executable(RunAllTests RunAllTests.cpp ${CLI_SOURCE_FILES} ${MOCK_SOURCE_FILES})
target_link_libraries(RunAllTests  ${CPPUTEST_LIB} ${CPPUTEST_EXT_LIB} ${OPENSSL_LIB} ${CRYPTO_LIB} "--coverage")
target_compile_options(RunAllTests PUBLIC --coverage)
