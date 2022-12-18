#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <limits.h>

#include "functions.h"

t_data g_data = {0};

void receive_packet(unsigned short destination_port)
{
	while (1)
	{
		struct data packet = {0};

		if (recvfrom(g_data.socket, &packet, sizeof(struct data), 0, g_data.destination.ai_addr, &g_data.destination.ai_addrlen) == -1)
			error(1, "recvfrom: %s\n", strerror(errno));

		if (packet.tcp.rst)
			g_data.result[destination_port] = CLOSED;
		else if (packet.tcp.ack)
			g_data.result[destination_port] = OPEN;
		else
			g_data.result[destination_port] = UNEXPECTED;
		break;
	}

	printf("Port %d: %s\n", destination_port, g_data.result[destination_port] == OPEN ? "OPEN" : "CLOSED");
}

void send_packet()
{
	struct data packet = {
		.tcp = {
			.source = htons(rand() % USHRT_MAX),
			.doff = 5 + OPT_SIZE / 4,
			.syn = 1,
		},
	};

	// maybe can be removed
	int mss = htons(1460);
	packet.options[0] = 2;
	packet.options[1] = 4;
	memcpy(packet.options + 2, &mss, 2);

	for (unsigned short port = 1; port <= 1024; port++)
	{
		// printf("Scanning port %d\r", port);
		// fflush(stdout);

		packet.tcp.dest = htons(port);
		packet.tcp.check = tcp_checksum(packet);

		if (sendto(g_data.socket, &packet, sizeof(struct tcphdr) + OPT_SIZE, 0, g_data.destination.ai_addr, g_data.destination.ai_addrlen) < 0)
			error(1, "sendto: %s\n", strerror(errno));

		receive_packet(port);
	}
}

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");
	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);
	srand(time(0));

	g_data.source_ip = get_interface_addr(AF_INET);
	g_data.destination = get_addr(av[1]);

	create_socket();
	send_packet();
	return 0;
}
