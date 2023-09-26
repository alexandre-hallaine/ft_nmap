#include "types.h"

#include <string.h>
#include <netdb.h>

unsigned short checksum(unsigned short *addr, size_t len)
{
	// add everything to a long data (to have more data than a short)
	unsigned long sum = 0;
	for (; len > sizeof(char); len -= sizeof(short))
		sum += *addr++;
	if (len == sizeof(char))
		sum += *(unsigned char *)addr;

	// deal with overflow
	unsigned char bits = sizeof(short) * 8;
	while (sum >> bits)
		sum = (sum & ((1 << bits) - 1)) + (sum >> bits);

	return (~sum);
}

void update_checksum(u_int8_t protocol, t_packet *packet, unsigned short packet_size)
{
    // complete an pseudo header and add it to a buffer in order to calculate the checksum (the pseudo header and the header isnt the same in both case)
	unsigned char ip_size = g_scan.destination.family == AF_INET ? sizeof(t_ipv4_pseudo_header) : sizeof(t_ipv6_pseudo_header);
	char buffer[ip_size + packet_size];
	if (g_scan.destination.family == AF_INET)
	{
		t_ipv4_pseudo_header pseudo_header = {
			.source_address = g_scan.interface.in.sin_addr.s_addr,
			.destination_address = g_scan.destination.addr.in.sin_addr.s_addr,
			.protocol = protocol,
			.length = htons(packet_size)};
		memcpy(buffer, &pseudo_header, ip_size);
	}
	else if (g_scan.destination.family == AF_INET6)
	{
		t_ipv6_pseudo_header pseudo_header = {
			.length = htonl(packet_size),
			.next_header = protocol};
		// we need to copy bytes because address is in difficult format and we cant copie it directly
		memcpy(pseudo_header.source_address, &g_scan.interface.in6.sin6_addr, sizeof(pseudo_header.source_address));
		memcpy(pseudo_header.destination_address, &g_scan.destination.addr.in6.sin6_addr, sizeof(pseudo_header.destination_address));
		memcpy(buffer, &pseudo_header, ip_size);
	}

	// add the real packet data to the pseudo header and calculate the checksum
	memcpy(buffer + ip_size, packet, packet_size);
	if (protocol == IPPROTO_TCP)
		packet->tcp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
	else if (protocol == IPPROTO_UDP)
		packet->udp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
}
