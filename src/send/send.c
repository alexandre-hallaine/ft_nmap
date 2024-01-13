#include "functions.h"

#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>

int create_socket()
{
    // Socket for sending TCP / UDP packets
	int sock = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));

	// need to remove the setsockopt to make docker work (error: Operation not permitted)
	// int optval = 1024 * 1024; // set buffer size to 1MB to avoid 'No buffer space available'
	// if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
	// 	error(1, "setsockopt: %s\n", strerror(errno));

	// need to double check why this is necessary
	if (g_scan.destination.family == AF_INET)
		bind(sock, (struct sockaddr *)&g_scan.interface.in, sizeof(g_scan.interface.in));
	else
		bind(sock, (struct sockaddr *)&g_scan.interface.in6, sizeof(g_scan.interface.in6));
	return sock;
}

void send_packet(t_technique technique)
{
	// create the packet with everything except the port and the checksum to have a base
	t_packet packet = create_packet(technique);
	g_scan.destination.protocol = technique == UDP ? IPPROTO_UDP : IPPROTO_TCP;
	int sock = create_socket();

	printf("Sending packet... (technique: %s)\n", get_technique_name(technique));
	for (unsigned short port = g_scan.options.port_min; port <= g_scan.options.port_max; port++)
	{
        g_scan.status[technique][port] = FILTERED;
        if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
            g_scan.status[technique][port] |= OPEN;

		//calculate the checksum
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
	}
	close(sock);
}
