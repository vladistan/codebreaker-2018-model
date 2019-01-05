#include "sim_types.h"


ssize_t mock_send(int socket, const void *buffer, size_t length, int flags);
int     mock_connect(int sock, struct sockaddr *addr, int len);
int	    mock_getsockname(int, struct sockaddr *, socklen_t *);
int     mock_recv(int socket, char * buf, int len, int flags);

void mock_recv_init(int state);

extern _BYTE mock_snd_store[3][STD_PACKET_SIZE];

#define recv mock_recv
#define send mock_send
#define connect mock_connect
#define getsockname mock_getsockname


