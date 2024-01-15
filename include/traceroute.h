#ifndef TRACEROUTE_H
#define TRACEROUTE_H

typedef struct
{
    int send_sock;
    int recv_sock;
    unsigned short sequence;
    unsigned short datalen;
} t_traceroute;

// network.c
void generate_socket();
void update_ttl(unsigned int ttl);

// recv.c
int recv_packet(struct sockaddr_storage *from, struct timeval last);

extern t_traceroute g_traceroute;

#endif
