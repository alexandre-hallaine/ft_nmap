#ifndef NMAP_H
#define NMAP_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <limits.h>
#include <stdbool.h>

typedef struct
{
	u_int32_t source_address;
	u_int32_t destination_address;
	u_int8_t zeros;
	u_int8_t protocol;
	u_int16_t length;
} t_ipv4_pseudo_header;

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
} t_protocol;

typedef struct
{
	t_protocol protocol;

	unsigned short port_min;
	unsigned short port_max;
} t_options;

typedef union
{
	struct tcphdr tcp;
	struct udphdr udp;
} t_packet;

typedef enum
{
	UNSCANNED = 0,

	OPEN,
	CLOSED,
	FILTERED,
	UNFILTERED,

	OPEN_FILTERED,
	CLOSED_FILTERED,
} t_status;

typedef struct
{
	t_addr interface;
	t_addrinfo destination;
	t_options options;

	int socket;					// used for receiving packets
	bool timeout;				// true if a timeout occured
	t_status status[USHRT_MAX]; // status of each port
} t_scan;

extern t_scan g_scan;
#endif
