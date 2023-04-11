#include "functions.h"

#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <stdio.h>

t_packet create_packet(t_protocol protocol)
{
	switch (protocol)
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
		error(3, "send_packet: protocol not supported\n");
		return (t_packet){0}; // to avoid warning
	}
}

char *get_protocol_name(t_protocol protocol)
{
	switch (protocol)
	{
	case ACK:
		return "ACK";
	case SYN:
		return "SYN";
	case FIN:
		return "FIN";
	case NUL:
		return "NUL";
	case XMAS:
		return "XMAS";
	case UDP:
		return "UDP";
	default:
		error(3, "send_packet: protocol not supported\n");
		return NULL; // to avoid warning
	}
}

void send_packet(t_protocol protocol)
{
	printf("Sending packet... (protocol: %s)\n", get_protocol_name(protocol));

	t_packet packet = create_packet(protocol);

	if ((g_scan.socket = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	int sock = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));

	for (unsigned short port = g_scan.options.port_min; port <= g_scan.options.port_max; port++)
	{
		unsigned short packet_size;

		if (protocol == UDP)
		{
			packet_size = sizeof(struct udphdr);
			packet.udp.dest = htons(port);
			packet.udp.check = 0;
		}
		else
		{
			packet_size = sizeof(struct tcphdr);
			packet.tcp.dest = htons(port);
			packet.tcp.check = 0;
		}
		update_checksum(protocol == UDP ? IPPROTO_UDP : IPPROTO_TCP, &packet, packet_size);

		if (sendto(sock, &packet, packet_size, 0, &g_scan.destination.addr.addr, g_scan.destination.addrlen) == -1)
			error(1, "sendto: %s\n", strerror(errno));
	}
}
