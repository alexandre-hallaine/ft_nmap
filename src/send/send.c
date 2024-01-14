#include "functions.h"

#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <pthread.h>

int create_socket(int protocol)
{
    // Socket for sending TCP / UDP packets
	int sock = socket(g_scan.family, SOCK_RAW, protocol);
	if (sock == -1)
		error(1, "socket: %s\n", strerror(errno));

	// need to remove the setsockopt to make docker work (error: Operation not permitted)
	// int optval = 1024 * 1024; // set buffer size to 1MB to avoid 'No buffer space available'
	// if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
	// 	error(1, "setsockopt: %s\n", strerror(errno));

    // Bind the socket to the interface
	if (g_scan.family == AF_INET)
		bind(sock, (struct sockaddr *)&g_scan.interface.in, sizeof(g_scan.interface.in));
	else
		bind(sock, (struct sockaddr *)&g_scan.interface.in6, sizeof(g_scan.interface.in6));
	return sock;
}

void *routine(void *arg)
{
    t_options *options = arg;
    t_technique technique;
    for (technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (options->techniques[technique])
            break;

    // Create a packet containing the header of the protocol we want to use (TCP or UDP)
    t_packet packet = create_packet(technique);
    unsigned short packet_size;
    int protocol;

    // Set the protocol and the size of the packet
    if (technique == UDP)
    {
        protocol = IPPROTO_UDP;
        packet_size = sizeof(struct udphdr);
    }
    else
    {
        protocol = IPPROTO_TCP;
        packet_size = sizeof(struct tcphdr);
    }

    // Create a raw socket for sending the packet
    int sock = create_socket(protocol);

    for (t_IP *IP = g_scan.IPs; IP != NULL; IP = IP->next)
        for (int port = 0; port <= USHRT_MAX; port++)
            if (options->ports[port])
            {
                // Set a default status for the port
                IP->status[technique][port] = FILTERED;
                if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
                    IP->status[technique][port] |= OPEN;

                // Set the destination port of the packet and calculate the checksum
                if (protocol == IPPROTO_TCP)
                {
                    packet.tcp.dest = htons(port);
                    packet.tcp.check = 0;
                }
                else
                {
                    packet.udp.dest = htons(port);
                    packet.udp.check = 0;
                }
                calculate_checksum(protocol, &packet, packet_size, IP);

                // Send the packet
                if (sendto(sock, &packet, packet_size, 0, &IP->destination.addr.addr, IP->destination.addrlen) == -1)
                    error(1, "sendto: %s\n", strerror(errno));
            }

    close(sock);
    free(arg);
    return NULL;
}

void dispatch(int amount, int *chunks, t_range chunk_range, bool *check)
{
    ft_bzero(chunks, sizeof(int) * (chunk_range.max - chunk_range.min));
    int current = chunk_range.min;
    for (int i = 0; i < amount; i++)
    {
        if (current >= chunk_range.max)
            current = chunk_range.min;
        current++;
        if (check != NULL && !check[current - 1])
            i--;
        else
            chunks[current - 1]++;
    }
}

void thread_send() {
    pthread_t thread[g_scan.options.thread_count];
    int id = 0;

    int chunks[TECHNIQUE_COUNT];
    dispatch(g_scan.options.thread_count, chunks, (t_range){0, TECHNIQUE_COUNT}, g_scan.options.techniques);

    for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (g_scan.options.techniques[technique])
        {
            int threads[chunks[technique]];
            dispatch(g_scan.options.ports_count, threads, (t_range){0, chunks[technique]}, NULL);

            int current = 0;
            for (int thread_no = 0; thread_no < chunks[technique]; thread_no++) {
                t_options *range = malloc(sizeof(t_options));
                int amount = threads[thread_no];

                for (int i = 0; i < TECHNIQUE_COUNT; i++)
                    range->techniques[i] = false;
                range->techniques[technique] = true;

                for (int i = 0; i <= USHRT_MAX; i++)
                    range->ports[i] = false;

                for (; current <= USHRT_MAX && amount != 0; current++)
                    if (g_scan.options.ports[current])
                    {
                        range->ports[current] = true;
                        amount--;
                    }

                printf("Sending packet... (technique: %s), (ports: %d)\n", get_technique_name(technique), threads[thread_no]);
                if (pthread_create(&thread[id++], NULL, routine, range) != 0)
                    error(1, "pthread_create: %s\n", strerror(errno));
            }
        }

    for (int i = 0; i < id; i++)
        pthread_join(thread[i], NULL);
}