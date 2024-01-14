#ifndef NMAP_H
#define NMAP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <pcap/pcap.h>

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

typedef union
{
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_storage storage;
} t_addr;

typedef struct
{
    t_addr addr;
    socklen_t addrlen;
} t_addrinfo;

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

typedef struct
{
    t_addrinfo destination;
    t_status status[TECHNIQUE_COUNT][USHRT_MAX]; // status of each port
    void *next;
} t_IP;

typedef struct {
    unsigned short min;
    unsigned short max;
} t_range;

typedef struct
{
    bool techniques[TECHNIQUE_COUNT];
    t_range port_range;
    unsigned short thread_count;
} t_options;

typedef union
{
    struct iphdr ipv4;
    struct ip6_hdr ipv6;
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
} t_packet;

typedef struct
{
    t_options options;
    t_addr interface;
    int family;
    t_IP *IPs;

    char filter[BUFSIZ];
    pcap_t *handle;
    bool stop;
} t_scan;

extern t_scan g_scan;
#endif
