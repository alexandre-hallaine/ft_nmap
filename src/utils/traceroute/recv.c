#include "traceroute.h"
#include "functions.h"

#include <stdio.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

int check_packet_icmp(char *buffer)
{
    if (g_scan.family == AF_INET)
        buffer += sizeof(struct iphdr); // when receiving in ipv4 there is an ip header before the icmp header
    struct icmphdr *icmp = (struct icmphdr *)buffer;

    if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP6_TIME_EXCEEDED)
    {
        struct icmphdr *icmp_sent;

        if (g_scan.family == AF_INET)
        {
            struct iphdr *ip = (struct iphdr *)(icmp + 1);
            icmp_sent = (struct icmphdr *)(ip + 1);

            if (ip->protocol != IPPROTO_ICMP)
                return -1;
        }
        else
        {
            struct ip6_hdr *ip = (struct ip6_hdr *)(icmp + 1);
            icmp_sent = (struct icmphdr *)(ip + 1);

            if (ip->ip6_nxt != IPPROTO_ICMPV6)
                return -1;
        };
        icmp->un.echo = icmp_sent->un.echo;
    }

    if (icmp->un.echo.id != htons(4242) || icmp->un.echo.sequence != htons(g_traceroute.sequence))
        return -1;

    if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP6_TIME_EXCEEDED)
        return 0;
    if (icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP6_ECHO_REPLY)
        return 1;

    if (icmp->type == ICMP_TIMESTAMPREPLY) {
        t_timestamp_data *data = (t_timestamp_data *)(icmp + 1);
        return data->originate_timestamp;
    }
    return -1;
}

int recv_packet(struct timeval last)
{
    size_t size = sizeof(struct icmphdr) + sizeof(struct udphdr);
    if (g_scan.family == AF_INET)
        size += sizeof(struct iphdr) * 2;
    else
        size += sizeof(struct ip6_hdr);

    char packet[size];
    bzero(packet, size);
    struct iovec iov = {.iov_base = packet, .iov_len = size};

    struct sockaddr_storage addr = {0};
    struct msghdr msg = {.msg_name = &addr, .msg_namelen = sizeof(addr), .msg_iov = &iov, .msg_iovlen = 1};

    if (recvmsg(g_traceroute.socket, &msg, 0) < 0)
    {
        if (g_scan.options.verbose == 2)
            printf(" *\n");
        return 0;
    }

    struct timeval time;
    gettimeofday(&time, NULL);

    int ret = check_packet_icmp(packet);
    if (ret < 0)
        return ret;


    if (g_scan.options.verbose == 2) {
        printf("%s", g_traceroute.current_IP->destination.name);
        printf(" %.3fms\n", (time.tv_sec - last.tv_sec) * 1000.0 + (time.tv_usec - last.tv_usec) / 1000.0);
    }
    return ret;
}
