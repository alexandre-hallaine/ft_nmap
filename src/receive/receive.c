#include "functions.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

void icmp_analyze(int technique, int port, struct icmphdr *icmp) {
    // Move to the pcap filter if possible
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
    // Skip ethernet header
    data += 16;

    int ip_size = g_scan.IPs->destination.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    t_packet *packet = (t_packet *) (data + ip_size);

    uint8_t protocol = g_scan.IPs->destination.family == AF_INET ? ((struct iphdr *) data)->protocol
                                                            : ((struct ip6_hdr *) data)->ip6_nxt;
    if (protocol == IPPROTO_ICMP) {
        data += sizeof(struct icmphdr) + ip_size; //go to old packet
        protocol = g_scan.IPs->destination.family == AF_INET ? ((struct iphdr *) data)->protocol
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
