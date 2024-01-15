#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/icmp6.h>

#include "functions.h"
#include "traceroute.h"

t_traceroute g_traceroute = {.sequence = 42, .datalen = 40};

void traceroute()
{
    generate_socket();

    char buffer[USHRT_MAX] = {0};
    for (size_t i = 0; i < sizeof(buffer); i++)
        buffer[i] = 66;

    struct icmphdr *icmp = (struct icmphdr *)buffer;
    ft_bzero(icmp, sizeof(*icmp));

    icmp->type = g_scan.family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->un.echo.id = htons(42);

    g_traceroute.datalen += sizeof(*icmp);
    icmp->checksum = checksum((unsigned short *)buffer, g_traceroute.datalen);

    for (t_IP *IP = g_scan.IPs; IP != NULL; IP = IP->next)
    {
        bool got_reply = 0;

        for (unsigned int ttl = 1; ttl <= 30 && !got_reply; ttl++)
        {
            update_ttl(ttl);
            // printf("%2d ", ttl);

            struct sockaddr_storage from = {0};
            ++g_traceroute.sequence;

            struct icmphdr *icmp = (struct icmphdr *)buffer;
            icmp->checksum -= htons(g_traceroute.sequence) - icmp->un.echo.sequence;
            icmp->un.echo.sequence = htons(g_traceroute.sequence);
            sendto(g_traceroute.send_sock, buffer, g_traceroute.datalen, 0, &IP->destination.addr.addr, IP->destination.addrlen);

            struct timeval time;
            gettimeofday(&time, NULL);

            int code;
            do
                code = recv_packet(&from, time);
            while (code < 0);
            if (code == 1)
            {
                got_reply = true;
                char ip[INET6_ADDRSTRLEN];
                if (g_scan.family == AF_INET)
                    inet_ntop(g_scan.family, &IP->destination.addr.in.sin_addr, ip, sizeof(ip));
                else if (g_scan.family == AF_INET6)
                    inet_ntop(g_scan.family, &IP->destination.addr.in6.sin6_addr, ip, sizeof(ip));
                printf("Host %s has %d hops", ip, ttl);
            }
        }
        printf("\n");
    }
    printf("\n");
}