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

void update_checksum(u_int8_t protocol_type, t_packet *packet, unsigned short packet_size)
{
	t_ipv4_pseudo_header pseudo_header = {
		.source_address = g_scan.interface.in.sin_addr.s_addr,
		.destination_address = g_scan.destination.addr.in.sin_addr.s_addr,
		.protocol = protocol_type,
		.length = htons(packet_size)};

	char buffer[sizeof(t_ipv4_pseudo_header) + packet_size];
	memcpy(buffer, &pseudo_header, sizeof(t_ipv4_pseudo_header));
	memcpy(buffer + sizeof(t_ipv4_pseudo_header), packet, packet_size);

	if (protocol_type == IPPROTO_TCP)
		packet->tcp.check = checksum((unsigned short *)buffer, sizeof(t_ipv4_pseudo_header) + packet_size);
	else if (protocol_type == IPPROTO_UDP)
		packet->udp.check = checksum((unsigned short *)buffer, sizeof(t_ipv4_pseudo_header) + packet_size);
}
