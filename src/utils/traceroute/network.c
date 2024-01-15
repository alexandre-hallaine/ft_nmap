#include "traceroute.h"
#include "functions.h"

#include <string.h>
#include <errno.h>
#include <netdb.h>

void generate_socket()
{
    g_traceroute.socket = socket(g_scan.family, SOCK_RAW, g_scan.family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    if (g_traceroute.socket < 0)
        error(1, "socket: %s\n", strerror(errno));

    struct timeval tv = {1, 0};
    setsockopt(g_traceroute.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ? error(1, "setsockopt: %s\n", strerror(errno)) : 0;

    int on = 1;
    if (g_scan.family != AF_INET && setsockopt(g_traceroute.socket, SOL_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
        error(1, "setsockopt: %s\n", strerror(errno));
}

void update_ttl(unsigned int ttl)
{
    int ret;
    if (g_scan.family == AF_INET)
        ret = setsockopt(g_traceroute.socket, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    else
        ret = setsockopt(g_traceroute.socket, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

    if (ret < 0)
        error(1, "setsockopt: %s\n", strerror(errno));
}
