#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/ip.h>

#include "functions.h"

void create_packet()
{
	// g_data.packet.tcp.source = htons(rand() % USHRT_MAX);
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.doff = 5 + OPT_SIZE / 4;
	g_data.packet.tcp.syn = 1;

	// maybe can be removed
	g_data.packet.options[0] = 2;
	g_data.packet.options[1] = 4;
	int mss = htons(1460);
	memcpy(g_data.packet.options + 2, &mss, 2);
}

void send_packet(unsigned short port)
{
	g_data.packet.tcp.dest = htons(port);
	g_data.packet.tcp.check = tcp_checksum(g_data.packet);

	if (sendto(g_data.socket, &g_data.packet, sizeof(struct tcphdr) + OPT_SIZE, 0, g_data.destination.ai_addr, g_data.destination.ai_addrlen) < 0)
		error(1, "sendto: %s\n", strerror(errno));
}

void receive_packet(unsigned short port)
{
	unsigned short source_port = ntohs(g_data.packet.tcp.source);
	unsigned short destination_port = port;

	size_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	char packet_buffer[packet_size];
	while (1)
	{
		if ((recvfrom(g_data.socket, packet_buffer, packet_size, 0, NULL, NULL)) < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				g_data.result[destination_port] = FILTERED;
			else
				error(1, "recvfrom: %s\n", strerror(errno));
			break;
		}

		struct iphdr *ip_header = (struct iphdr *)packet_buffer;
		if (ip_header->protocol != IPPROTO_TCP)
			continue;

		t_packet *packet = (t_packet *)(packet_buffer + sizeof(struct iphdr));
		if (ntohs(packet->tcp.source) != destination_port)
			continue;
		if (ntohs(packet->tcp.dest) != source_port)
			continue;

		if (packet->tcp.rst)
			g_data.result[destination_port] = CLOSED;
		else if (packet->tcp.ack)
			g_data.result[destination_port] = OPEN;
		break;
	}
}
