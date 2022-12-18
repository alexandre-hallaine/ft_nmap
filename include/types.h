#ifndef NMAP_H
#define NMAP_H

#include <netinet/tcp.h>
#include <limits.h>

#define OPT_SIZE 4

enum state
{
	UNSCANNED = 0,
	UNEXPECTED,
	FILTERED,
	OPEN,
	CLOSED,
	UNFILTERED,
};

typedef struct
{
	struct tcphdr tcp;
	char options[OPT_SIZE];
} t_packet;

typedef struct
{
	u_int32_t source_address;
	u_int32_t destination_address;
	u_int8_t zeros;
	u_int8_t protocol;
	u_int16_t tcp_length;
} t_ipv4_pseudo_header;

typedef struct
{
	size_t start_port;
	size_t end_port;
} t_options;

typedef struct
{
	int socket;
	uint32_t source_ip;
	struct addrinfo destination;

	t_packet packet;
	char result[1024];
	size_t index;
	t_options options;
} t_data;

extern t_data g_data;

#endif
