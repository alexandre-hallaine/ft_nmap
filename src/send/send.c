#include "functions.h"

#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>

void send_packet(t_technique technique)
{
    // Create a packet containing the header of the protocol we want to use (TCP or UDP)
    t_packet packet = create_packet(technique);
    unsigned short packet_size;

    // Set the protocol and the size of the packet
    if (technique == UDP)
    {
        g_scan.destination.protocol = IPPROTO_UDP;
        packet_size = sizeof(struct udphdr);
    }
    else
    {
        g_scan.destination.protocol = IPPROTO_TCP;
        packet_size = sizeof(struct tcphdr);
    }

    // Create a raw socket for sending the packet
    int sock = socket(g_scan.destination.family, SOCK_RAW, g_scan.destination.protocol);
    if (sock == -1)
        error(1, "socket: %s\n", strerror(errno));

    // int optval = 1024 * 1024; // set buffer size to 1MB to avoid 'No buffer space available'
	// if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
	// 	error(1, "setsockopt: %s\n", strerror(errno));

    printf("Sending packet... (technique: %s)\n", get_technique_name(technique));

    for (unsigned short port = g_scan.options.port_min; port <= g_scan.options.port_max; port++)
    {
        // Set a default status for the port
        g_scan.status[technique][port] = FILTERED;
        if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
            g_scan.status[technique][port] |= OPEN;

        // Set the destination port of the packet and calculate the checksum
        if (g_scan.destination.protocol == IPPROTO_TCP)
        {
            packet.tcp.dest = htons(port);
            packet.tcp.check = 0;
        }
        else
        {
            packet.udp.dest = htons(port);
            packet.udp.check = 0;
        }
        calculate_checksum(g_scan.destination.protocol, &packet, packet_size);

        // Send the packet
        if (sendto(sock, &packet, packet_size, 0, &g_scan.destination.addr.addr, g_scan.destination.addrlen) == -1)
            error(1, "sendto: %s\n", strerror(errno));
    }

    close(sock);
}
