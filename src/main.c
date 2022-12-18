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

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");
	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);
	srand(time(0));

	g_data.source_ip = get_interface(AF_INET);
	g_data.destination = get_info(av[1]);

	create_socket();
	create_packet();

	for (unsigned short port = 22; port <= 80; port++)
	{
		printf("Scanning port %d\r", port);
		fflush(stdout);

		send_packet(port);
		receive_packet(port);
	}
	printf("Port scanning finished\n");

	for (unsigned short port = 1; port <= 1024; port++)
		if (g_data.result[port] == OPEN)
			printf("Port %d is open\n", port);
	return 0;
}
