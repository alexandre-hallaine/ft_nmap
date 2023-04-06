#include "functions.h"

#include <string.h>
#include <errno.h>
#include <netinet/ip.h>

void create_packet_ack()
{
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.window = htons(1024);
	g_data.packet.tcp.doff = 5;

	g_data.packet.tcp.ack = 1;
}

void create_packet_syn()
{
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.window = htons(1024);
	g_data.packet.tcp.doff = 5;

	g_data.packet.tcp.syn = 1;

	// maybe can be removed
	// g_data.packet.tcp.doff = 5 + OPT_SIZE / 4;
	// g_data.packet.options[0] = 2;
	// g_data.packet.options[1] = 4;
	// int mss = htons(1460);
	// memcpy(g_data.packet.options + 2, &mss, 2);
}

void create_packet_fin()
{
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.window = htons(1024);
	g_data.packet.tcp.doff = 5;

	g_data.packet.tcp.fin = 1;
}

void create_packet_null()
{
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.window = htons(1024);
	g_data.packet.tcp.doff = 5;
}

void create_packet_xmas()
{
	g_data.packet.tcp.source = htons(4242);
	g_data.packet.tcp.window = htons(1024);
	g_data.packet.tcp.doff = 5;

	g_data.packet.tcp.fin = 1;
	g_data.packet.tcp.psh = 1;
	g_data.packet.tcp.urg = 1;
}

void send_packet_tcp(unsigned short port)
{
	unsigned short values = g_data.packet.tcp.doff * 4;

	g_data.packet.tcp.dest = htons(port);
	g_data.packet.tcp.check = packet_checksum(TCP, g_data.packet, values);

	if (sendto(g_data.socket, &g_data.packet, sizeof(struct tcphdr) + values, 0, &g_data.destination.ai_addr, g_data.destination.ai_addrlen) < 0)
		error(1, "sendto: %s\n", strerror(errno));
}
