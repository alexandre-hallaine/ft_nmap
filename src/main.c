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
		default:
			return "unknown";
	}
}

void result()
{
	int count[6] = {0};

	for (unsigned int index = 0; index < g_data.index; index++)
		count[(int)g_data.result[index]]++;

	int default_type;
	if (count[OPEN] > count[CLOSED] && count[OPEN] > count[FILTERED] && count[OPEN] > count[UNFILTERED])
		default_type = OPEN;
	else if (count[CLOSED] > count[OPEN] && count[CLOSED] > count[FILTERED] && count[CLOSED] > count[UNFILTERED])
		default_type = CLOSED;
	else if (count[FILTERED] > count[OPEN] && count[FILTERED] > count[CLOSED] && count[FILTERED] > count[UNFILTERED])
		default_type = FILTERED;
	else if (count[UNFILTERED] > count[OPEN] && count[UNFILTERED] > count[CLOSED] && count[UNFILTERED] > count[FILTERED])
		default_type = UNFILTERED;
	else
		default_type = UNEXPECTED;

	printf("Not shown: %d ports on state %s\n", count[default_type] , get_type(default_type));
	for (unsigned int index = 0; index < g_data.index; index++)
	{
		if (g_data.result[index] != default_type)
			printf("Port %d: %s\n", index + (int)g_data.options.start_port, get_type(g_data.result[index]));
	}
}

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");
	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);
	srand(time(0));

	g_data.source_ip = get_interface(AF_INET);
	g_data.destination = get_info(av[1]);
	g_data.options.start_port = 22;
	g_data.options.end_port = 80;

	create_socket();
	//create_packet_syn();
	create_packet_ack();

	for (unsigned short port = g_data.options.start_port; port <= g_data.options.end_port; port++, g_data.index++)
	{
		printf("Scanning port %d\r", port);
		fflush(stdout);

		// send_packet_syn(port);
		send_packet_ack(port);
		// receive_packet_syn(port);
		receive_packet_ack(port);
	}
	printf("Port scanning finished\n");
	
	result();
	return 0;
}
