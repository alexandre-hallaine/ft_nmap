#ifndef NMAP_H
#define NMAP_H

#include <netinet/tcp.h>
#include <limits.h>

#define OPT_SIZE 4
#define TYPE_SIZE 7

typedef enum
{
	UNSCANNED = 0,
	UNEXPECTED,
	FILTERED,
	OPEN,
	CLOSED,
	UNFILTERED,
	OPEN_FILTERED,
} t_type;

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
	unsigned short start_port;
	unsigned short end_port;
} t_options;

typedef struct {
  int ai_family;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr ai_addr;
} t_addrinfo;

typedef struct
{
	int socket;
	uint32_t source_ip;
	t_addrinfo destination;

	t_packet packet;
	t_type result[USHRT_MAX];
	t_options options;
} t_data;

extern t_data g_data;

#endif
