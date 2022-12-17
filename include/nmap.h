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
	UNFILTERED,
	UNEXPECTED,

	OPEN,
	OPEN_FILTERED,
	OPEN_OR_FILTERED,

	CLOSED,
	CLOSED_FILTERED,
	CLOSED_OR_FILTERED,
};

typedef struct
{
	struct addrinfo res;
	uint32_t own_addr;

	int sock;
	int closed;
	int filtered;
} t_data;

extern t_data g_data;

#endif
