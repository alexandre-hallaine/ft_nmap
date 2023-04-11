#include "types.h"

#include <arpa/inet.h>

t_packet create_packet_ack()
{
	t_packet packet = {0};
	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;

	packet.tcp.ack = 1;
	return packet;
}

t_packet create_packet_syn()
{
	t_packet packet = {0};
	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;

	packet.tcp.syn = 1;
	return packet;

	// maybe can be removed
	// packet.tcp.doff = 5 + OPT_SIZE / 4;
	// packet.options[0] = 2;
	// packet.options[1] = 4;
	// int mss = htons(1460);
	// memcpy(packet.options + 2, &mss, 2);
}

t_packet create_packet_fin()
{
	t_packet packet = {0};
	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;

	packet.tcp.fin = 1;
	return packet;
}

t_packet create_packet_null()
{
	t_packet packet = {0};
	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;
	return packet;
}

t_packet create_packet_xmas()
{
	t_packet packet = {0};
	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;

	packet.tcp.fin = 1;
	packet.tcp.psh = 1;
	packet.tcp.urg = 1;
	return packet;
}

t_packet create_packet_udp()
{
	t_packet packet = {0};
	packet.udp.source = htons(4242);
	packet.udp.len = htons(sizeof(struct udphdr));
	return packet;
}
