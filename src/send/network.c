#include "functions.h"

#include <string.h>
#include <errno.h>

t_packet_header create_packet(t_technique technique)
{
    t_packet_header packet = {0};

    // For UDP, we only need to set the source port and the length
    if (technique == UDP)
    {
        packet.udp.source = htons(technique);
        packet.udp.len = htons(sizeof(struct udphdr));
        return packet;
    }

    // For TCP, we need to set the source port, the window size and the data offset
    packet.tcp.source = htons(technique);
    packet.tcp.doff = 5; // 5 * 4 bytes (32 bits) = 20 bytes (the size of the header)

    // And we need to set the flags
    packet.tcp.ack = technique == ACK;
    packet.tcp.syn = technique == SYN;
    packet.tcp.fin = technique == FIN || technique == XMAS;
    packet.tcp.psh = technique == XMAS;
    packet.tcp.urg = technique == XMAS;

    // Used for debugging purposes to see which technique is used
    // printf("\nack: %d, syn: %d, fin: %d, psh: %d, urg: %d\n", packet.tcp.ack, packet.tcp.syn, packet.tcp.fin, packet.tcp.psh, packet.tcp.urg);
    return packet;
}

int create_socket(int protocol)
{
    // Socket for sending TCP / UDP packets
	int sock = socket(g_scan.options.family, SOCK_RAW, protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));

     // set buffer size to 1MB to avoid 'No buffer space available'
	int optval = 1024 * 1024;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
		error(1, "setsockopt: %s\n", strerror(errno));

    // Bind the socket to the interface
	if (g_scan.options.family == AF_INET)
		bind(sock, (struct sockaddr *)&g_scan.interface.ipv4, sizeof(g_scan.interface.ipv4));
	else
		bind(sock, (struct sockaddr *)&g_scan.interface.ipv6, sizeof(g_scan.interface.ipv6));
	return sock;
}
