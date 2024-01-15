#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/icmp6.h>

#include "functions.h"
#include "traceroute.h"

t_traceroute g_traceroute = {.sequence = 0, .datalen = 40};

int scan(int ttl, t_IP *IP, char buffer[USHRT_MAX])
{
    update_ttl(ttl);
    if (g_scan.options.verbose)
        printf("%2d ", ttl);

    struct sockaddr_storage from = {0};
    struct icmphdr *icmp = (struct icmphdr *)buffer;

    ++g_traceroute.sequence;
    icmp->checksum -= htons(g_traceroute.sequence) - icmp->un.echo.sequence;
    icmp->un.echo.sequence = htons(g_traceroute.sequence);

    sendto(g_traceroute.send_sock, buffer, g_traceroute.datalen, 0, &IP->destination.addr.addr, IP->destination.addrlen);

    struct timeval time;
    gettimeofday(&time, NULL);

    int code;
    do
        code = recv_packet(&from, time);
    while (code < 0);

    char ip[INET6_ADDRSTRLEN];
    if (g_scan.family == AF_INET)
        inet_ntop(g_scan.family, &IP->destination.addr.in.sin_addr, ip, sizeof(ip));
    else if (g_scan.family == AF_INET6)
        inet_ntop(g_scan.family, &IP->destination.addr.in6.sin6_addr, ip, sizeof(ip));

    if (g_traceroute.type == TRACEROUTE)
    {
        if (code == 1)
        printf("Host %s has %d hops\n", ip, ttl);
    }
    else if (g_traceroute.type == PING)
    {
        if (code == 1)
            printf("Host %s is up\n", ip);
        else if (code == 0) {
            printf("Host %s is down\n", ip);
            IP->is_down = true;
        }
    }
    return (code);
}

void traceroute(t_scan_type type)
{
    if (type == TIMESTAMP && g_scan.family == AF_INET6)
        error(1, "Timestamping is not supported with IPv6.\n");

    g_traceroute.type = type;
    generate_socket();

    char buffer[USHRT_MAX] = {0};
    struct icmphdr *icmp = (struct icmphdr *)buffer;

    g_traceroute.datalen += sizeof(struct icmphdr);
    for (unsigned short i = sizeof(struct icmphdr) + 1; i < g_traceroute.datalen; i++)
        buffer[i] = 66; // 42 in hex ᕕ( ᐛ )ᕗ

    icmp->type = g_scan.family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->un.echo.id = htons(4242);
    icmp->checksum = checksum((unsigned short *)buffer, g_traceroute.datalen);

    for (t_IP *IP = g_scan.IPs; IP != NULL; IP = IP->next)
        if (type == TRACEROUTE)
        {
            bool got_reply = 0;
            for (unsigned int ttl = 1; ttl <= 64 && !got_reply; ttl++)
                got_reply = scan(ttl, IP, buffer);
            if (!got_reply)
            {
                printf("Host did not reply, max hops reached. Probably down.\n");
                IP->is_down = true;
            }
        }
        else if (type == PING)
            scan(255, IP, buffer);
    printf("\n");
}