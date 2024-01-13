#include "functions.h"

#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <pthread.h>

int create_socket()
{
    // Socket for sending TCP / UDP packets
	int sock = socket(g_scan.IPs->destination.family, SOCK_RAW, g_scan.IPs->destination.protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));

	// need to remove the setsockopt to make docker work (error: Operation not permitted)
	// int optval = 1024 * 1024; // set buffer size to 1MB to avoid 'No buffer space available'
	// if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
	// 	error(1, "setsockopt: %s\n", strerror(errno));

    // Bind the socket to the interface
	if (g_scan.IPs->destination.family == AF_INET)
		bind(sock, (struct sockaddr *)&g_scan.interface.in, sizeof(g_scan.interface.in));
	else
		bind(sock, (struct sockaddr *)&g_scan.interface.in6, sizeof(g_scan.interface.in6));
	return sock;
}

//void send_packet_solo(t_technique technique, unsigned short small, unsigned short big)
//{
//    // Create a packet containing the header of the protocol we want to use (TCP or UDP)
//    t_packet packet = create_packet(technique);
//    unsigned short packet_size;
//
//    // Set the protocol and the size of the packet
//    if (technique == UDP)
//    {
//        g_scan.IPs->destination.protocol = IPPROTO_UDP;
//        packet_size = sizeof(struct udphdr);
//    }
//    else
//    {
//        g_scan.IPs->destination.protocol = IPPROTO_TCP;
//        packet_size = sizeof(struct tcphdr);
//    }
//
//    // Create a raw socket for sending the packet
//    int sock = create_socket();
//
//    // printf("Sending packet... (technique: %s)\n", get_technique_name(technique));
//
//    for (unsigned short port = small; port <= big; port++)
//    {
//        // printf("Sending packet... (technique: %s), (port: %d)\n", get_technique_name(technique), port);
//        // Set a default status for the port
//        g_scan.status[technique][port] = FILTERED;
//        if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
//            g_scan.status[technique][port] |= OPEN;
//
//        // Set the destination port of the packet and calculate the checksum
//        if (g_scan.IPs->destination.protocol == IPPROTO_TCP)
//        {
//            packet.tcp.dest = htons(port);
//            packet.tcp.check = 0;
//        }
//        else
//        {
//            packet.udp.dest = htons(port);
//            packet.udp.check = 0;
//        }
//        calculate_checksum(g_scan.IPs->destination.protocol, &packet, packet_size);
//
//        // Send the packet
//        if (sendto(sock, &packet, packet_size, 0, &g_scan.IPs->destination.addr.addr, g_scan.IPs->destination.addrlen) == -1)
//            error(1, "sendto: %s\n", strerror(errno));
//    }
//
//    close(sock);
//}

void *routine(void *arg)
{
    t_range *range = arg;
    // Create a raw socket for sending the packet
    int sock = create_socket();

    for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (g_scan.options.techniques[technique])
        {
            // Create a packet containing the header of the protocol we want to use (TCP or UDP)
            t_packet packet = create_packet(technique);
            unsigned short packet_size;

            // Set the protocol and the size of the packet
            if (technique == UDP)
            {
                g_scan.IPs->destination.protocol = IPPROTO_UDP;
                packet_size = sizeof(struct udphdr);
            }
            else
            {
                g_scan.IPs->destination.protocol = IPPROTO_TCP;
                packet_size = sizeof(struct tcphdr);
            }

            for (unsigned short port = range->min; port <= range->max; port++)
            {
                // Set a default status for the port
                g_scan.status[technique][port] = FILTERED;
                if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
                    g_scan.status[technique][port] |= OPEN;

                // Set the destination port of the packet and calculate the checksum
                if (g_scan.IPs->destination.protocol == IPPROTO_TCP)
                {
                    packet.tcp.dest = htons(port);
                    packet.tcp.check = 0;
                }
                else
                {
                    packet.udp.dest = htons(port);
                    packet.udp.check = 0;
                }
                calculate_checksum(g_scan.IPs->destination.protocol, &packet, packet_size);

                // Send the packet
                if (sendto(sock, &packet, packet_size, 0, &g_scan.IPs->destination.addr.addr, g_scan.IPs->destination.addrlen) == -1)
                    error(1, "sendto: %s\n", strerror(errno));
            }
        }

    close(sock);
    free(arg);
    return NULL;
}

void thread_send() {
    int techniques = 0;
    for (int i = 0; i < TECHNIQUE_COUNT; i++)
        if (g_scan.options.techniques[i])
            techniques++;

    if (g_scan.options.thread_count < techniques) {
        g_scan.options.thread_count = techniques;
        printf("Warning: too less threads, using %d instead\n", techniques);
    }

    int chunks[TECHNIQUE_COUNT] = {0};
    {
        int thread = 0;
        t_technique technique = 0;
        while (thread < g_scan.options.thread_count) {
            if (technique == TECHNIQUE_COUNT)
                technique = 0;
            if (!g_scan.options.techniques[technique++])
                continue;
            chunks[technique - 1]++;
            thread++;
        }
    }

    pthread_t thread[g_scan.options.thread_count];
    int id = 0;
    for (int i = 0; i < TECHNIQUE_COUNT; i++)
        if (g_scan.options.techniques[i]) {
            int scans = g_scan.options.port_range.max - g_scan.options.port_range.min;

            int padding = scans / chunks[i];
            int rest = scans % chunks[i];
            int current_port = g_scan.options.port_range.min;

            printf("scans: %d, threads: %d, padding: %d, rest: %d\n", scans, chunks[i], padding, rest);

            for (int thread_no = 0; thread_no < chunks[i]; thread_no++) {
                if (thread_no == chunks[i] - 1)
                    padding += rest;

                t_range *range = malloc(sizeof(t_range));
                range->min = current_port;
                range->max = current_port += padding;

                printf("thread %d: %d - %d\n", thread_no, range->min, range->max);
            }
        }
}