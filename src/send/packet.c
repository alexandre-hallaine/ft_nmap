#include "types.h"

t_packet create_packet(t_technique technique)
{
    // needs some comments (not chatgpt :) )
	t_packet packet = {0};
	if (technique == UDP)
	{
		packet.udp.source = htons(4242);
		packet.udp.len = htons(sizeof(struct udphdr));
		return packet;
	}

	packet.tcp.source = htons(4242);
	packet.tcp.window = htons(1024);
	packet.tcp.doff = 5;

	packet.tcp.ack = technique == ACK;
	packet.tcp.syn = technique == SYN;
	packet.tcp.fin = technique == FIN || technique == XMAS;
	packet.tcp.psh = technique == XMAS;
	packet.tcp.urg = technique == XMAS;

	// printf("\nack: %d, syn: %d, fin: %d, psh: %d, urg: %d\n", packet.tcp.ack, packet.tcp.syn, packet.tcp.fin, packet.tcp.psh, packet.tcp.urg);
	return packet;
}
