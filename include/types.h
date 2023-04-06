#ifndef NMAP_H
#define NMAP_H

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <limits.h>

typedef struct
{
	u_int32_t source_address;
	u_int32_t destination_address;
	u_int8_t zeros;
	u_int8_t protocol;
	u_int16_t tcp_length;
} t_ipv4_pseudo_header;

typedef union
{
	struct in_addr in;
	struct in6_addr in6;
} t_addr;

typedef struct
{
	int ai_family;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr ai_addr;
} t_addrinfo;

typedef enum
{
	TCP = 0,
	UDP,
} t_type;

typedef union
{
	struct tcphdr tcp;
	struct udphdr udp;
} t_packet;

typedef struct
{
	t_type type;
	unsigned short start_port;
	unsigned short end_port;
} t_options;

typedef enum
{
	UNSCANNED = 0,
	UNEXPECTED,

	OPEN,
	OPEN_FILTERED,
	CLOSED,

	FILTERED,
	UNFILTERED,
} t_reponse;
#define RESPONSE_MAX 7

typedef struct
{
	int socket;
	t_addr source_ip;
	t_addrinfo destination;

	t_packet packet;
	t_options options;

	t_reponse result[USHRT_MAX];
} t_data;

extern t_data g_data;

#endif
