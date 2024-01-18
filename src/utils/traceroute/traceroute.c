#include "functions.h"
#include "traceroute.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/icmp6.h>

t_traceroute g_traceroute = { .sequence = 0, .datalen = 40 };

int scan(int ttl, char buffer[USHRT_MAX])
{
    update_ttl(ttl);
    if (g_scan.options.verbose == 2)
        printf("%d ", ttl);

    struct icmphdr *icmp = (struct icmphdr *)buffer;

    ++g_traceroute.sequence;
    icmp->checksum -= htons(g_traceroute.sequence) - icmp->un.echo.sequence;
    icmp->un.echo.sequence = htons(g_traceroute.sequence);

    sendto(g_traceroute.socket, buffer, g_traceroute.datalen, 0, &g_traceroute.current_IP->addr.base, g_traceroute.current_IP->addrlen);

    struct timeval time;
    gettimeofday(&time, NULL);

    int code;
    do
        code = recv_packet(time);
    while (code < 0);

    if (g_traceroute.type == TRACEROUTE)
    {
        if (code > 0)
            printf("Host %s has %d hops\n", g_traceroute.current_IP->name, ttl);
    }
    else if (g_traceroute.type == PING)
    {
        if (code == 0)
        {
            printf("Host %s is down\n", g_traceroute.current_IP->name);
            g_traceroute.current_IP->is_down = true;
        }
        else if (code > 0)
            printf("Host %s is up\n", g_traceroute.current_IP->name);
    }
    else if (g_traceroute.type == TIMESTAMP)
    {
        if (code == 0)
            printf("No response from host %s\n", g_traceroute.current_IP->name);
        else if (code > 0)
        {
            struct timeval tv;
            char buf[BUFSIZ];

            gettimeofday(&tv, NULL);
            tv.tv_sec -= code / 1000;
            tv.tv_usec -= (code % 1000) * 1000;

            strftime(buf, sizeof(buf), "%c", localtime(&tv.tv_sec));
            printf("Host %s up since %s\n", g_traceroute.current_IP->name, buf);
        }
    }
    return (code);
}

void traceroute(t_scan_type type)
{
    switch (type)
    {
        case TRACEROUTE:
            printf("Sending traceroute...\n");
            break;
        case PING:
            printf("Sending ping...\n");
            break;
        case TIMESTAMP:
            printf("Sending timestamp...\n");
            break;
    }

    g_traceroute.type = type;
    generate_socket();

    char buffer[USHRT_MAX] = {0};
    struct icmphdr *icmp = (struct icmphdr *)buffer;

    g_traceroute.datalen += sizeof(struct icmphdr);
    for (unsigned short i = sizeof(struct icmphdr) + 1; i < g_traceroute.datalen; i++)
        buffer[i] = 66; // 42 in hex ᕕ( ᐛ )ᕗ

    if (type == TIMESTAMP)
    {
        if (g_scan.options.family == AF_INET6)
        {
            printf("Timestamping is not supported with IPv6.\n");
            return ;
        }
        icmp->type = ICMP_TIMESTAMP;
    }
    else
        icmp->type = g_scan.options.family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->un.echo.id = htons(4242);
    icmp->checksum = checksum((unsigned short *)buffer, g_traceroute.datalen);

    for (g_traceroute.current_IP = g_scan.ip; g_traceroute.current_IP != NULL; g_traceroute.current_IP = g_traceroute.current_IP->next)
        if (type == TRACEROUTE)
        {
            bool got_reply = 0;
            for (unsigned int ttl = 1; ttl <= 64 && !got_reply; ttl++)
                got_reply = scan(ttl, buffer);
            if (!got_reply)
            {
                printf("Host did not reply, max hops reached. Probably down.\n");
                g_traceroute.current_IP->is_down = true;
            }
        }
        else
        {
            int ttl = 255;
            if (type == PING)
                scan(ttl, buffer);
            else if (type == TIMESTAMP)
                scan(ttl, buffer);
        }
    printf("\n");
}