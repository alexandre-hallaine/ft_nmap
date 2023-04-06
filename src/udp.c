#include "functions.h"

#include <string.h>
#include <errno.h>
#include <netinet/ip.h>

void create_packet_udp()
{
	g_data.packet.udp.source = htons(4242);
	g_data.packet.udp.len = htons(sizeof(struct udphdr));
}

void send_packet_udp(unsigned short port)
{
	g_data.packet.udp.dest = htons(port);
	g_data.packet.udp.check = packet_checksum(UDP, g_data.packet, sizeof(struct udphdr));

	if (sendto(g_data.socket, &g_data.packet, sizeof(struct udphdr), 0, &g_data.destination.ai_addr, g_data.destination.ai_addrlen) == -1)
		error(1, "sendto: %s\n", strerror(errno));
}
