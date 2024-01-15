#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "traceroute.h"
#include "functions.h"

void generate_socket()
{
    g_traceroute.recv_sock = socket(g_scan.family, SOCK_RAW, g_scan.family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    g_traceroute.send_sock = g_traceroute.recv_sock;

    if (g_traceroute.send_sock < 0)
        error(1, "socket: %s\n", strerror(errno));

    struct timeval tv = {0, 300000};
    setsockopt(g_traceroute.recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ? error(1, "setsockopt: %s\n", strerror(errno)) : 0;

    int on = 1;
    if (g_scan.family != AF_INET && setsockopt(g_traceroute.recv_sock, SOL_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
        error(1, "setsockopt: %s\n", strerror(errno));
}

void update_ttl(unsigned int ttl)
{
    int ret;
    g_scan.family == AF_INET ? (ret = setsockopt(g_traceroute.send_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) : (ret = setsockopt(g_traceroute.send_sock, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)));

    if (ret < 0)
        error(1, "setsockopt: %s\n", strerror(errno));
}