#ifndef NMAP_H
#define NMAP_H

#include <netinet/tcp.h>
#include <limits.h>

#define OPT_SIZE 4

enum state
{
	UNEXPECTED = 0,
	FILTERED,

	OPEN,
	CLOSED,
};

struct data
{
	struct tcphdr tcp;
	char options[OPT_SIZE];
};

struct ipv4_pseudo_header
{
	u_int32_t source_address;
	u_int32_t destination_address;
	u_int8_t zeros;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

typedef struct
{
	int socket;
	uint32_t source_ip;
	struct addrinfo destination;

	struct data packet;
	char result[USHRT_MAX];
} t_data;

extern t_data g_data;

#endif
