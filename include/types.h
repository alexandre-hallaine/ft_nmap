#ifndef NMAP_H
#define NMAP_H

#include <netinet/in.h>
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
	int family;
	int protocol;
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

typedef struct
{
	bool techniques[TECHNIQUE_COUNT];

	unsigned short port_min;
	unsigned short port_max;
} t_options;

typedef union
{
	struct tcphdr tcp;
	struct udphdr udp;
    struct icmphdr icmp;
} t_packet;

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
	t_options options;
	t_addr interface;
	t_addrinfo destination;

	t_status status[TECHNIQUE_COUNT][USHRT_MAX]; // status of each port
    char filter[BUFSIZ];
    pcap_t *handle;
} t_scan;

extern t_scan g_scan;
#endif
