#include "functions.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>

void icmp_analyze(int technique, int port, struct icmphdr *icmp, t_IP *IP) {
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
        IP->status[technique][port] = CLOSED;
    else
        IP->status[technique][port] = FILTERED;

    if (g_scan.options.verbose) {
        printf("%s: port %d is ", get_technique_name(technique), port);
        print_status_name(IP->status[technique][port]);
    }
}

void packet_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *data) {
    // Skip ethernet header
    data += 16;

    int ip_size = g_scan.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    t_packet *header = (t_packet *) data;
    t_packet *packet = (t_packet *) (data + ip_size);
    uint8_t protocol = g_scan.family == AF_INET ? header->ipv4.protocol : header->ipv6.ip6_nxt;

    t_IP *IP;
    for (IP = g_scan.IPs; IP; IP = IP->next)
        if (g_scan.family == AF_INET && IP->destination.addr.in.sin_addr.s_addr == header->ipv4.saddr)
            break;
        else if (g_scan.family == AF_INET6 && !memcmp(&IP->destination.addr.in6.sin6_addr, &header->ipv6.ip6_src, sizeof(struct in6_addr)))
            break;
    if (!IP)
        return;

    int technique;
    int port;
    if (protocol == IPPROTO_ICMP) {
        data += sizeof(struct icmphdr) + ip_size; //go to old packet
        protocol = g_scan.family == AF_INET ? ((struct iphdr *) data)->protocol
                                                        : ((struct ip6_hdr *) data)->ip6_nxt;

        t_packet *packet_old = (t_packet *) (data + ip_size);
        technique = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.source) : ntohs(packet_old->udp.source);
        port = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.dest) : ntohs(packet_old->udp.dest);
        icmp_analyze(technique, port, &packet->icmp, IP);
    } else {
        technique = protocol == IPPROTO_TCP ? ntohs(packet->tcp.dest) : ntohs(packet->udp.dest);
        port = protocol == IPPROTO_TCP ? ntohs(packet->tcp.source) : ntohs(packet->udp.source);

        if (technique == UDP || packet->tcp.syn)
            IP->status[technique][port] = OPEN;
        else if (packet->tcp.rst)
            IP->status[technique][port] = technique == ACK ? UNFILTERED : CLOSED;
    }

    // If there is a response, reset the alarm to 5 seconds
    alarm(5);
    if (g_scan.options.verbose) {
        printf("%s: port %d is ", get_technique_name(technique), port);
        print_status_name(IP->status[technique][port]);
    }
}
