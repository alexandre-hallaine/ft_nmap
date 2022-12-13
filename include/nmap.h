#ifndef NMAP_H
#define NMAP_H

#define OPT_SIZE 20
#define BUFFER_SIZE 4096

struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

enum state
{
	FILTERED = 0,
	OPEN,
	CLOSED,
	UNEXPECTED,
	OPEN_FILTERED,
	CLOSED_FILTERED,
	OPEN_OR_FILTERED,
	CLOSED_OR_FILTERED,
	UNFILTERED,
};

typedef struct
{
	int sock;
	struct addrinfo *res;
	struct sockaddr_in *host;
	int closed;
	int filtered;
} t_data;

extern t_data g_data;

#endif
