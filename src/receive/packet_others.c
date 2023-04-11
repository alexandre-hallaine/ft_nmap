#include "functions.h"

#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>

void receive_packet_others(unsigned short port)
{
	unsigned short source_port = ntohs(g_data.packet.tcp.source);
	unsigned short destination_port = port;

	size_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
	char packet_buffer[packet_size];
	while (1)
	{
		if ((recvfrom(g_data.socket, packet_buffer, packet_size, 0, NULL, NULL)) < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				g_data.result[destination_port] = OPEN_FILTERED;
			else
				error(1, "recvfrom: %s\n", strerror(errno));
			break;
		}

		struct iphdr *ip_header = (struct iphdr *)packet_buffer;
		if (ip_header->protocol != IPPROTO_TCP)
			continue;

		struct tcphdr *packet = (struct tcphdr *)(packet_buffer + sizeof(struct iphdr));
		if (ntohs(packet->source) != destination_port)
			continue;
		if (ntohs(packet->dest) != source_port)
			continue;

		if (packet->rst)
			g_data.result[destination_port] = CLOSED;
		else
			g_data.result[destination_port] = UNEXPECTED;
		break;
	}
}