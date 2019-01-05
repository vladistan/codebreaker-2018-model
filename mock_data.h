
#ifndef REPLICA_MOCK_DATA_H
#define REPLICA_MOCK_DATA_H

#include "sim_types.h"
#include "client.h"

extern _BYTE loc_enc_ki[0x200LL];
extern _BYTE victim_id_b[32];
extern _BYTE otp[6];

extern _BYTE expected_first_sent_pack[STD_PACKET_SIZE];
extern _BYTE rcv_pkt_2[STD_PACKET_SIZE];
extern _BYTE rcv_pkt_3[STD_PACKET_SIZE];
extern _BYTE snd_pkt_2[STD_PACKET_SIZE];
extern _BYTE snd_pkt_3[STD_PACKET_SIZE];


#endif //REPLICA_MOCK_DATA_H
