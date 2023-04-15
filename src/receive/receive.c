#include "functions.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

void timeout(int sig)
{
	(void)sig;
	g_scan.timeout = true;
}

void icmp_packet(t_technique technique, struct icmphdr icmp, t_packet *packet)
{
	if (icmp.type != ICMP_UNREACH)
		return;

	if (icmp.code != ICMP_UNREACH_HOST &&
		icmp.code != ICMP_UNREACH_PROTOCOL &&
		icmp.code != ICMP_UNREACH_PORT &&
		icmp.code != ICMP_UNREACH_NET_PROHIB &&
		icmp.code != ICMP_UNREACH_HOST_PROHIB &&
		icmp.code != ICMP_UNREACH_FILTER_PROHIB)
		return;

	unsigned port = g_scan.destination.protocol == IPPROTO_TCP ? ntohs(packet->tcp.dest) : ntohs(packet->udp.dest);
	if (icmp.code == ICMP_UNREACH_PORT && technique == UDP)
		g_scan.status[technique][port] = CLOSED;
	else
		g_scan.status[technique][port] = FILTERED;
}

void default_packet(t_technique technique, t_packet *packet)
{
	unsigned short port = g_scan.destination.protocol == IPPROTO_TCP ? ntohs(packet->tcp.source) : ntohs(packet->udp.source);
	switch (technique)
	{
	case ACK:
		if (packet->tcp.rst)
			g_scan.status[technique][port] = UNFILTERED;
		break;
	case SYN:
		if (packet->tcp.syn && packet->tcp.ack)
			g_scan.status[technique][port] = OPEN;
		else if (packet->tcp.rst)
			g_scan.status[technique][port] = CLOSED;
		break;
	case FIN:
	case NUL:
	case XMAS:
		if (packet->tcp.rst)
			g_scan.status[technique][port] = CLOSED;
		break;
	case UDP:
		g_scan.status[technique][port] = OPEN;
		break;
	}
}

void receive_packet(t_technique technique)
{
	(void)technique;

	g_scan.timeout = false;
	signal(SIGALRM, timeout);
	alarm(1); // 1 second timeout

	char buffer[sizeof(struct ip6_hdr) + sizeof(t_packet) + sizeof(struct ip6_hdr) + sizeof(t_packet)]; // ip + packet + icmp error data
	t_addr source;
	socklen_t source_len = sizeof(source);

	while (!g_scan.timeout)
	{
		uint8_t protocol;
		if (recvfrom(g_scan.socket, buffer, sizeof(buffer), MSG_DONTWAIT, &source.addr, &source_len) > 0)
			protocol = g_scan.destination.protocol;
		else if (recvfrom(g_scan.socket_icmp, buffer, sizeof(buffer), MSG_DONTWAIT, &source.addr, &source_len) > 0)
			protocol = IPPROTO_ICMP;
		else
			continue;

		if (memcmp(&source.addr, &g_scan.destination.addr, source_len))
			continue;

		unsigned char ip_size;
		if (g_scan.destination.family == AF_INET)
			ip_size = sizeof(struct iphdr);
		else if (g_scan.destination.family == AF_INET6)
			ip_size = sizeof(struct ip6_hdr);
		else
			continue;

		t_packet *packet = (t_packet *)buffer;
		if (g_scan.destination.family == AF_INET)
			packet = (t_packet *)((char *)packet + ip_size);

		if (protocol == IPPROTO_ICMP)
			icmp_packet(technique, packet->icmp, (t_packet *)((char *)packet + sizeof(struct icmphdr) + ip_size));
		else
			default_packet(technique, packet);
	}

	print_result(technique);
}
