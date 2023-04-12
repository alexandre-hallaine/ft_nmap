#include "functions.h"

#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>

t_packet create_packet(t_technique technique)
{
	switch (technique)
	{
	case ACK:
		return create_packet_ack();
	case SYN:
		return create_packet_syn();
	case FIN:
		return create_packet_fin();
	case NUL:
		return create_packet_null();
	case XMAS:
		return create_packet_xmas();
	case UDP:
		return create_packet_udp();
	default:
		error(3, "create_packet: unknown technique\n");
		return (t_packet){0}; // to avoid warning
	}
}

void send_packet(t_technique technique)
{
	printf("Sending packet... (technique: %s)\n", get_technique_name(technique));

	t_packet packet = create_packet(technique);
	g_scan.destination.protocol = technique == UDP ? IPPROTO_UDP : IPPROTO_TCP;

	// use to receive response (it will saved every response)
	{
		if ((g_scan.socket = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol)) == -1)
			error(1, "socket: %s\n", strerror(errno));
		if ((g_scan.socket_icmp = socket(g_scan.destination.family, SOCK_RAW, IPPROTO_ICMP)) == -1)
			error(1, "socket: %s\n", strerror(errno));
	}

	int sock = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));
	int optval = 1024 * 1024; // set buffer size to 1MB to avoid 'No buffer space available'
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
		error(1, "setsockopt: %s\n", strerror(errno));

	for (unsigned short port = g_scan.options.port_min; port <= g_scan.options.port_max; port++)
	{
		unsigned short packet_size;

		if (g_scan.destination.protocol == IPPROTO_TCP)
		{
			packet_size = sizeof(struct tcphdr);
			packet.tcp.dest = htons(port);
			packet.tcp.check = 0;
		}
		else
		{
			packet_size = sizeof(struct udphdr);
			packet.udp.dest = htons(port);
			packet.udp.check = 0;
		}
		update_checksum(g_scan.destination.protocol, &packet, packet_size);

		if (sendto(sock, &packet, packet_size, 0, &g_scan.destination.addr.addr, g_scan.destination.addrlen) == -1)
			error(1, "sendto: %s\n", strerror(errno));

		if (g_scan.status[technique][port] != UNSCANNED)
			continue;
		g_scan.status[technique][port] = FILTERED;
		if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
			g_scan.status[technique][port] |= OPEN;
	}
}
