#include "types.h"

#include <string.h>
#include <netdb.h>

unsigned short checksum(unsigned short *addr, size_t len)
{
	unsigned long sum = 0;
	for (; len > sizeof(char); len -= sizeof(short))
		sum += *addr++;
	if (len == sizeof(char))
		sum += *(unsigned char *)addr;
	unsigned char bits = sizeof(short) * 8;
	while (sum >> bits)
		sum = (sum & ((1 << bits) - 1)) + (sum >> bits);
	return (~sum);
}

unsigned short packet_checksum(t_type type, t_packet packet, unsigned short packet_size)
{
	t_ipv4_pseudo_header pseudo_header = {
		.source_address = g_data.source_ip.in.s_addr,
		.destination_address = ((struct sockaddr_in *)&g_data.destination.ai_addr)->sin_addr.s_addr,
		.protocol = IPPROTO_TCP,
		.tcp_length = htons(packet_size)};

	if (type == TCP)
		packet.tcp.check = 0;
	else if (type == UDP)
		packet.udp.check = 0;

	char buffer[sizeof(t_ipv4_pseudo_header) + packet_size];
	memcpy(buffer, &pseudo_header, sizeof(t_ipv4_pseudo_header));
	memcpy(buffer + sizeof(t_ipv4_pseudo_header), &packet, packet_size);

	return checksum((unsigned short *)buffer, sizeof(buffer));
}
