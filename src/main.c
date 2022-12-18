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
#include <sys/types.h>
#include <sys/socket.h>

#include "functions.h"

t_data g_data = {0};

void receive_packet(unsigned short source_port, unsigned short destination_port)
{
	size_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	char packet_buffer[packet_size];
	while (1)
	{
		if ((recvfrom(g_data.socket, packet_buffer, packet_size, 0, NULL, NULL)) < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				g_data.result[htons(destination_port)] = FILTERED;
			else
				error(1, "recvfrom: %s\n", strerror(errno));
			break;
		}

		struct iphdr *ip_header = (struct iphdr *)packet_buffer;
		if (ip_header->protocol != IPPROTO_TCP)
			continue;

		struct data *packet = (struct data *)(packet_buffer + sizeof(struct iphdr));
		if (ntohs(packet->tcp.source) != ntohs(destination_port))
			continue;
		if (ntohs(packet->tcp.dest) != ntohs(source_port))
			continue;

		if (packet->tcp.rst)
			g_data.result[htons(destination_port)] = CLOSED;
		else if (packet->tcp.ack)
			g_data.result[htons(destination_port)] = OPEN;
		else
			g_data.result[htons(destination_port)] = UNEXPECTED;
		break;
	}
}

void send_packet()
{
	struct data packet = {
		.tcp = {
			// .source = htons(rand() % USHRT_MAX),
			.source = htons(4242),
			.doff = 5 + OPT_SIZE / 4,
			.syn = 1,
		},
	};

	// maybe can be removed
	int mss = htons(1460);
	packet.options[0] = 2;
	packet.options[1] = 4;
	memcpy(packet.options + 2, &mss, 2);

	//testing a few ports because of the time it takes to scan all of them
	for (unsigned short port = 22; port <= 80; port++)
	{
		printf("Scanning port %d\r", port);
		fflush(stdout);

		packet.tcp.dest = htons(port);
		packet.tcp.check = tcp_checksum(packet);

		if (sendto(g_data.socket, &packet, sizeof(struct tcphdr) + OPT_SIZE, 0, g_data.destination.ai_addr, g_data.destination.ai_addrlen) < 0)
			error(1, "sendto: %s\n", strerror(errno));

		receive_packet(packet.tcp.source, packet.tcp.dest);
	}
	printf("Scanning finished\n");
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

	for (unsigned short port = 1; port <= 1024; port++)
		if (g_data.result[port] == OPEN)
			printf("Port %d is open\n", port);
	return 0;
}
