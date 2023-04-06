#include "functions.h"

#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/ip.h>

void receive_packet_syn(unsigned short port)
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
		else
			g_data.result[destination_port] = UNEXPECTED;
		break;
	}
}
