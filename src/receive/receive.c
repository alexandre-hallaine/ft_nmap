#include "functions.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

void timeout(int sig)
{
	(void)sig;
	g_scan.timeout = true;
}

void icmp_packet(t_protocol protocol, struct icmphdr icmp)
{
	if (icmp.type != ICMP_UNREACH)
		return;

	if (icmp.code == ICMP_UNREACH_HOST ||
		icmp.code == ICMP_UNREACH_PROTOCOL ||
		icmp.code == ICMP_UNREACH_PORT ||
		icmp.code == ICMP_UNREACH_NET_PROHIB ||
		icmp.code == ICMP_UNREACH_HOST_PROHIB ||
		icmp.code == ICMP_UNREACH_FILTER_PROHIB)
	{
		// need to get the port!
	}
	(void)protocol;
}

void receive_packet(t_protocol protocol)
{
	(void)protocol;

	g_scan.timeout = false;
	signal(SIGALRM, timeout);
	alarm(1); // 1 second timeout

	char buffer[sizeof(struct iphdr) + sizeof(t_packet)];
	t_addr source;
	socklen_t source_len = sizeof(source);
	uint8_t protocol_id = protocol == UDP ? IPPROTO_UDP : IPPROTO_TCP;

	while (!g_scan.timeout)
	{
		if (recvfrom(g_scan.socket, buffer, sizeof(buffer), 0, &source.addr, &source_len) == -1)
			error(1, "recvfrom: %s\n", strerror(errno));
		if (memcmp(&source.addr, &g_scan.destination.addr, source_len))
			continue;

		struct iphdr *ip_header = (struct iphdr *)buffer;
		t_packet *packet = (t_packet *)(buffer + sizeof(struct iphdr));

		// if (ip_header->protocol == IPPROTO_ICMP)
		// 	icmp_packet(protocol, packet.icmp);
		if (ip_header->protocol != protocol_id)
			continue;

		unsigned short port;
		if (protocol == UDP)
			port = ntohs(packet->udp.source);
		else
			port = ntohs(packet->tcp.source);

		printf("port: %d\n", port);
	}
}
