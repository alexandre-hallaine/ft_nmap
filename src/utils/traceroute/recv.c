#include "traceroute.h"
#include "functions.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

void update_addr(struct sockaddr_storage *dst, struct sockaddr_storage *src, int family)
{
    ft_memcpy(dst, src, sizeof(struct sockaddr_storage));

    if (g_scan.options.verbose) {
        char ip_str[INET6_ADDRSTRLEN];
        struct hostent *host;

        if (family == AF_INET)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)src;
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
            host = gethostbyaddr(&addr->sin_addr, sizeof(struct in_addr), AF_INET);
        }
        else
        {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)src;
            inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, INET6_ADDRSTRLEN);
            host = gethostbyaddr(&addr->sin6_addr, sizeof(struct in6_addr), AF_INET6);
        }

        // print the host name only if it is needed
        if (!host || strcmp(host->h_name, ip_str) == 0)
            printf("%s", ip_str);
        else
            printf("%s(%s)", host->h_name, ip_str);
    }
}

int check_packet_icmp(char *data)
{
    if (g_scan.family == AF_INET)
        data += sizeof(struct iphdr); // when receiving in ipv4 there is an ip header before the icmp header
    struct icmphdr *icmp = (struct icmphdr *)data;

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
    // if (icmp->type == ICMP_TIMESTAMPREPLY)
    //     return 2;
    return -1;
}

int recv_packet(struct sockaddr_storage *from, struct timeval last)
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

    if (recvmsg(g_traceroute.recv_sock, &msg, 0) < 0)
    {
        if (g_scan.options.verbose)
            printf(" *\n");
        return 0;
    }

    struct timeval time;
    gettimeofday(&time, NULL);

    int ret = check_packet_icmp(packet);
    if (ret < 0)
        return ret;

    if (memcmp(&addr, from, sizeof(addr)) != 0)
        update_addr(from, &addr, g_scan.family);

    if (g_scan.options.verbose)
        printf(" %.3fms\n", (time.tv_sec - last.tv_sec) * 1000.0 + (time.tv_usec - last.tv_usec) / 1000.0);
    return ret;
}
