#ifndef NMAP_H
#define NMAP_H

#include <stdbool.h>
#include <limits.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>

#define PORT_MIN 1
#define PORT_MAX 1024

#define MAX_IPS 42

typedef struct
{
    u_int32_t source_address;
    u_int32_t destination_address;
    u_int8_t zeros;
    u_int8_t protocol;
    u_int16_t length;
} t_ipv4_pseudo_header;

typedef struct
{
    u_int32_t source_address[4];
    u_int32_t destination_address[4];
    u_int32_t length;
    u_int8_t zeros[3];
    u_int8_t next_header;
} t_ipv6_pseudo_header;

typedef struct {
    int min;
    int max;
} t_range;

typedef union
{
    struct iphdr ipv4;
    struct ip6_hdr ipv6;
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
} t_packet_header;

typedef enum
{
    ACK = 0,
    SYN,
    FIN,
    NUL,
    XMAS,
    UDP,
} t_technique;
#define TECHNIQUE_COUNT 6

typedef enum
{
    UNSCANNED = 0,

    OPEN = 1 << 0,
    CLOSED = 1 << 1,
    FILTERED = 1 << 2,
    UNFILTERED = 1 << 3,
} t_status;

typedef union
{
    struct sockaddr base;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    struct sockaddr_storage storage;
} t_sockaddr;

typedef struct
{
    t_sockaddr addr;
    socklen_t addrlen;

    char name[NI_MAXHOST];
    bool is_down;

    t_status status[TECHNIQUE_COUNT][USHRT_MAX + 1]; // status of each port

    void *next;
} t_IP;

typedef struct
{
    bool technique[TECHNIQUE_COUNT];
    int technique_count;
    bool port[USHRT_MAX + 1];
    int port_count;
    unsigned short thread_count;

    int family;
    int verbose;
    bool ping;
    bool traceroute;
    bool timestamp;
    bool file;
} t_options;

typedef struct
{
    t_options options;
    t_sockaddr interface;
    t_IP *ip;
    int ip_count;

    char filter[BUFSIZ];
    pcap_t *handle;
    bool stop_pcap;
} t_scan;

extern t_scan g_scan;

#endif
