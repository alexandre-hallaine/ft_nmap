#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include "types.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <stdint.h>

typedef enum
{
    PING,
    TRACEROUTE,
    TIMESTAMP,
} t_scan_type;

typedef struct
{
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
} t_timestamp_data;

typedef struct
{
    int socket;
    
    unsigned short sequence;
    unsigned short datalen;

    t_scan_type type;
    t_IP *current_IP;
} t_traceroute;

extern t_traceroute g_traceroute;

// network.c
void generate_socket();
void update_ttl(unsigned int ttl);

// recv.c
int recv_packet(struct timeval last);

// traceroute.c
void traceroute(t_scan_type type);

#endif
