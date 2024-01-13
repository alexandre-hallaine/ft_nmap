#include "functions.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

//void receive_packet(t_technique technique)
//{
//    char buffer[sizeof(struct ip6_hdr) + sizeof(t_packet) + sizeof(struct ip6_hdr) + sizeof(t_packet)]; // ip + packet + icmp error data
//	t_addr source;
//	socklen_t source_len = sizeof(source);
//    uint8_t protocol;
//    unsigned char ip_size;
//
//	g_scan.timeout = false;
//	signal(SIGALRM, timeout);
//	alarm(1); // 1 second timeout
//    // perhaps slightly more time ?
//
//	while (!g_scan.timeout)
//	{
//		if (recvfrom(g_scan.socket, buffer, sizeof(buffer), MSG_DONTWAIT, &source.addr, &source_len) > 0)
//			protocol = g_scan.destination.protocol;
//		else if (recvfrom(g_scan.socket_icmp, buffer, sizeof(buffer), MSG_DONTWAIT, &source.addr, &source_len) > 0)
//			protocol = IPPROTO_ICMP;
//		else
//			continue;
//
//		if (memcmp(&source.addr, &g_scan.destination.addr, source_len))
//			continue;
//
//        t_packet *packet = (t_packet *)buffer;
//		if (g_scan.destination.family == AF_INET)
//        {
//			ip_size = sizeof(struct iphdr);
//            packet = (t_packet *)((char *)packet + ip_size);
//        }
//		else
//			ip_size = sizeof(struct ip6_hdr);
//
//        if (protocol == IPPROTO_ICMP) {
//            struct icmphdr icmp = packet->icmp;
//            packet = (t_packet *)((char *)packet + sizeof(struct icmphdr) + ip_size);
//
//            if (icmp.type != ICMP_UNREACH)
//                return;
//
//            if (icmp.code != ICMP_UNREACH_HOST &&
//                icmp.code != ICMP_UNREACH_PROTOCOL &&
//                icmp.code != ICMP_UNREACH_PORT &&
//                icmp.code != ICMP_UNREACH_NET_PROHIB &&
//                icmp.code != ICMP_UNREACH_HOST_PROHIB &&
//                icmp.code != ICMP_UNREACH_FILTER_PROHIB)
//                return;
//
//            unsigned port = g_scan.destination.protocol == IPPROTO_TCP ? ntohs(packet->tcp.dest) : ntohs(packet->udp.dest);
//            if (technique == UDP && icmp.code == ICMP_UNREACH_PORT)
//                g_scan.status[technique][port] = CLOSED;
//            else
//                g_scan.status[technique][port] = FILTERED;
//        }
//		else
//        {
//            unsigned short port = g_scan.destination.protocol == IPPROTO_TCP ? ntohs(packet->tcp.source) : ntohs(packet->udp.source);
//            if (technique == UDP || packet->tcp.syn)
//                g_scan.status[technique][port] = OPEN;
//            else if (packet->tcp.rst)
//                g_scan.status[technique][port] = technique == ACK ? UNFILTERED : CLOSED;
//        }
//	}
//
//	close(g_scan.socket);
//	close(g_scan.socket_icmp);
//	print_result(technique);
//}

void icmp_analyze(int technique, int port, struct icmphdr *icmp) {
    if (icmp->type != ICMP_UNREACH)
        return;

    if (icmp->code != ICMP_UNREACH_HOST &&
        icmp->code != ICMP_UNREACH_PROTOCOL &&
        icmp->code != ICMP_UNREACH_PORT &&
        icmp->code != ICMP_UNREACH_NET_PROHIB &&
        icmp->code != ICMP_UNREACH_HOST_PROHIB &&
        icmp->code != ICMP_UNREACH_FILTER_PROHIB)
        return;

    if (technique == UDP && icmp->code == ICMP_UNREACH_PORT)
        g_scan.status[technique][port] = CLOSED;
    else
        g_scan.status[technique][port] = FILTERED;
}

void packet_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *data) {
    data += 16; // skip ethernet header

    int ip_size = g_scan.destination.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    t_packet *packet = (t_packet *) (data + ip_size);

    uint8_t protocol = g_scan.destination.family == AF_INET ? ((struct iphdr *) data)->protocol
                                                            : ((struct ip6_hdr *) data)->ip6_nxt;
    if (protocol == IPPROTO_ICMP) {
        data += sizeof(struct icmphdr) + ip_size; //go to old packet
        protocol = g_scan.destination.family == AF_INET ? ((struct iphdr *) data)->protocol
                                                        : ((struct ip6_hdr *) data)->ip6_nxt;

        t_packet *packet_old = (t_packet *) (data + ip_size);
        int technique = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.source) : ntohs(packet_old->udp.source);
        int port = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.dest) : ntohs(packet_old->udp.dest);
        icmp_analyze(technique, port, &packet->icmp);
    } else {
        int technique = protocol == IPPROTO_TCP ? ntohs(packet->tcp.dest) : ntohs(packet->udp.dest);
        int port = protocol == IPPROTO_TCP ? ntohs(packet->tcp.source) : ntohs(packet->udp.source);

        if (technique == UDP || packet->tcp.syn)
            g_scan.status[technique][port] = OPEN;
        else if (packet->tcp.rst)
            g_scan.status[technique][port] = technique == ACK ? UNFILTERED : CLOSED;
    }
}
