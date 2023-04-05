#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#include "functions.h"

t_data g_data = {0};

void create_socket()
{
	if ((g_data.socket = socket(g_data.destination.ai_family, SOCK_RAW, g_data.destination.ai_protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	struct timeval timeout = {(long)0, 200000};
	if (setsockopt(g_data.socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		error(1, "setsockopt: %s\n", strerror(errno));
}

char *get_type(int type)
{
	switch (type)
	{
		case OPEN:
			return "open";
		case CLOSED:
			return "closed";
		case FILTERED:
			return "filtered";
		case UNFILTERED:
			return "unfiltered";
		case UNEXPECTED:
			return "unexpected";
		case OPEN_FILTERED:
			return "open|filtered";
		default:
			return "unknown";
	}
}

void result()
{
	unsigned short amount[TYPE_SIZE] = {0};
	for (unsigned short index = g_data.options.start_port; index <= g_data.options.end_port; index++)
		if (g_data.result[index] != UNSCANNED)
			amount[g_data.result[index]]++;
	
	t_type default_type = 0;
	for (t_type type = 0; type < TYPE_SIZE; type++)
		if (amount[type] > amount[default_type])
			default_type = type;
	printf("Not shown: %d ports on state %s\n", amount[default_type], get_type(default_type));

	if (amount[default_type] == g_data.options.end_port - g_data.options.start_port + 1)
		return;

	printf("PORT\tSTATE\n");
	for (unsigned short index = g_data.options.start_port; index <= g_data.options.end_port; index++)
		if (g_data.result[index] != UNSCANNED && g_data.result[index] != default_type)
			printf("%d\t%s\n", index, get_type(g_data.result[index]));
}

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");
	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);

	printf("--- Loading nmap ---\n");
	g_data.source_ip = get_interface(AF_INET);
	g_data.destination = get_info(av[1]);
	g_data.options.start_port = 22;
	g_data.options.end_port = 80;
	printf("--- nmap loaded ---\n\n");

	create_socket();
	// create_packet_ack();
	create_packet_syn();
	// create_packet_fin();
	//create_packet_null();
	// create_packet_xmas();

	for (unsigned short port = g_data.options.start_port; port <= g_data.options.end_port; port++)
	{
		printf("Scanning port %d\r", port);
		fflush(stdout);

		send_packet_tcp(port);
		// send_packet_syn(port);
		// send_packet_others(port);
		// receive_packet_others(port);
		// receive_packet_ack(port);
		// receive_packet_syn(port);
	}
	printf("Port scanning finished\n");
	
	result();
	return 0;
}
