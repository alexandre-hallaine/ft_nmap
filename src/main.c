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
		case UNEXPECTED:
			return "unexpected";
		default:
			return "unknown";
	}
}

void result()
{
	size_t closed = 0, filtered = 0, open = 0;

	for (unsigned int index = 0; index < 1024; index++)
	{
		if (g_data.result[index] == CLOSED)
			closed++;
		else if (g_data.result[index] == FILTERED)
			filtered++;
		else if (g_data.result[index] == OPEN)
			open++;
	}

	int default_type;
	if (open > closed && open > filtered)
		default_type = OPEN;
	else if (closed > open && closed > filtered)
		default_type = CLOSED;
	else if (filtered > open && filtered > closed)
		default_type = FILTERED;
	else
		default_type = UNEXPECTED;

	for (unsigned int index = 0; index < 1024; index++)
	{
		if (g_data.result[index] == default_type)
			continue;
		if (g_data.result[index] == UNSCANNED)
			continue;
		printf("Port %d: %s\n", index + (int)g_data.options.start_port, get_type(g_data.result[index]));
	}
	printf("%ld ports are %s\n", closed, get_type(default_type));
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
	g_data.options.start_port = 400;
	g_data.options.end_port = 1000;

	create_socket();
	create_packet();

	for (unsigned short port = g_data.options.start_port; port <= g_data.options.end_port; port++, g_data.index++)
	{
		printf("Scanning port %d\r", port);
		fflush(stdout);

		send_packet(port);
		receive_packet(port);
	}
	printf("Port scanning finished\n");
	
	result();
	return 0;
}
