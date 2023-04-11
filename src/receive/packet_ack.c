#include "functions.h"

#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

void receive_packet_ack(unsigned short port)
{
	size_t packet_size = sizeof(g_data.packet);
	if (g_data.destination.ai_family == AF_INET)
		packet_size += sizeof(struct iphdr);
	else if (g_data.destination.ai_family == AF_INET6)
		packet_size += sizeof(struct ip6_hdr);
	char packet_buffer[packet_size];

	(void)port;

	while (1)
	{
		if ((recvfrom(g_data.socket, packet_buffer, packet_size, MSG_EOR, &g_data.destination.ai_addr, &g_data.destination.ai_addrlen)) == -1)
			break;

		struct iphdr *ip_header = (struct iphdr *)packet_buffer;
		if (ip_header->protocol != IPPROTO_TCP)
			continue;

		struct tcphdr *packet = (struct tcphdr *)(packet_buffer + sizeof(struct iphdr));

		if (ntohs(packet->dest) != ntohs(g_data.packet.tcp.source))
			continue;

		unsigned short destination_port = ntohs(packet->source);

		if (packet->rst)
			g_data.result[destination_port] = UNFILTERED;
		else
			g_data.result[destination_port] = UNEXPECTED;
		break;
	}
}
