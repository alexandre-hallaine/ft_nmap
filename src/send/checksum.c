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

void update_checksum(u_int8_t protocol, t_packet *packet, unsigned short packet_size)
{

	unsigned short ip_size;
	if (g_scan.destination.family == AF_INET)
		ip_size = sizeof(t_ipv4_pseudo_header);
	else if (g_scan.destination.family == AF_INET6)
		ip_size = sizeof(t_ipv6_pseudo_header);

	char buffer[sizeof(t_ipv6_pseudo_header) + packet_size];
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
		memcpy(pseudo_header.source_address, &g_scan.interface.in6.sin6_addr, sizeof(pseudo_header.source_address));
		memcpy(pseudo_header.destination_address, &g_scan.destination.addr.in6.sin6_addr, sizeof(pseudo_header.destination_address));
		memcpy(buffer, &pseudo_header, ip_size);
	}

	memcpy(buffer + ip_size, packet, packet_size);
	if (protocol == IPPROTO_TCP)
		packet->tcp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
	else if (protocol == IPPROTO_UDP)
		packet->udp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
}
