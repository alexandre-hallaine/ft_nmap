#include <string.h>
#include <errno.h>
#include <netinet/ip.h>

#include "functions.h"

void send_packet_tcp(unsigned short port)
{
	unsigned short values = (g_data.packet.tcp.doff - 5) * 4;

	g_data.packet.tcp.dest = htons(port);
	g_data.packet.tcp.check = tcp_checksum(g_data.packet, values);

	if (sendto(g_data.socket, &g_data.packet, sizeof(struct tcphdr) + values, 0, &g_data.destination.ai_addr, g_data.destination.ai_addrlen) < 0)
		error(1, "sendto: %s\n", strerror(errno));
}
