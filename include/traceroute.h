#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <sys/socket.h>
#include <sys/time.h>

typedef enum
{
    PING,
    TRACEROUTE,
    TIMESTAMP,
} t_scan_type;

typedef struct
{
    int send_sock;
    int recv_sock;
    unsigned short sequence;
    unsigned short datalen;
    t_scan_type type;
} t_traceroute;

extern t_traceroute g_traceroute;

// network.c
void generate_socket();
void update_ttl(unsigned int ttl);

// recv.c
int recv_packet(struct sockaddr_storage *from, struct timeval last);

// traceroute.c
void traceroute(t_scan_type type);

#endif
