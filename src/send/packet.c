#include "types.h"

t_packet create_packet(t_technique technique)
{
	t_packet packet = {0};
	if (technique == UDP)
	{
		packet.udp.source = htons(4242);
		packet.udp.len = htons(sizeof(struct udphdr));
		return packet;
	}

	packet.tcp.source = htons(4242); // we set the source port to 4242 to find easily the response in wire shark (and in pcap in the future)
	packet.tcp.window = htons(1024); // i dont know why it is important (need to double check)
	packet.tcp.doff = 5; // 5 * 32bits = 20bytes (the size of the header)

	// we set the flags according to the technique
	packet.tcp.ack = technique == ACK;
	packet.tcp.syn = technique == SYN;
	packet.tcp.fin = technique == FIN || technique == XMAS;
	packet.tcp.psh = technique == XMAS;
	packet.tcp.urg = technique == XMAS;

	// to check if all set flags are correct
	// printf("\nack: %d, syn: %d, fin: %d, psh: %d, urg: %d\n", packet.tcp.ack, packet.tcp.syn, packet.tcp.fin, packet.tcp.psh, packet.tcp.urg);
	return packet;
}
