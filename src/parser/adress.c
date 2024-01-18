#include "functions.h"

#include <errno.h>
#include <string.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

t_sockaddr get_interface()
{
    // getting the list of all interface
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
        error(1, "getifaddrs: %s\n", strerror(errno));

    // getting the interface with the broadcast flag (where we can send packet)
    t_sockaddr addr = {0};
    struct ifaddrs *tmp = NULL;
    for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
        if ((tmp->ifa_flags & IFF_BROADCAST) && tmp->ifa_addr->sa_family == g_scan.options.family) // ifa_addr always exists if IFF_BROADCAST is set (we dont need to check if it is NULL)
        {
            // storing the interface address
            ft_memcpy(&addr, tmp->ifa_addr, sizeof(t_sockaddr));
            break;
        }

    if (tmp == NULL)
        error(1, "get_interface: no interface found\n");
    else {
            // print the interface name and the ip address
            char ip[INET6_ADDRSTRLEN] = {0};
            inet_ntop(g_scan.options.family, g_scan.options.family == AF_INET ? (void *)&addr.ipv4.sin_addr : (void *)&addr.ipv6.sin6_addr, ip, sizeof(ip));
            printf("Interface: %s(%s)\n", tmp->ifa_name, ip);
    }

    freeifaddrs(ifaddr);
    return addr;
}

t_IP get_ip(char *host)
{
    // getting the address info of the host with the canonname (the name of the host eg: google.com)
    struct addrinfo *res, hints = {.ai_flags = AI_CANONNAME, .ai_family = g_scan.options.family};
    if ((errno = getaddrinfo(host, NULL, &hints, &res)) != 0)
        error(1, "getaddrinfo: %s\n", gai_strerror(errno));

    t_IP ip = { .addrlen = res->ai_addrlen };
    // copying the address bytes to avoid losing information
    ft_memcpy(&ip.addr, res->ai_addr, res->ai_addrlen);

    // save the ip of the host
    char ip_str[INET6_ADDRSTRLEN] = {0};
    inet_ntop(res->ai_family, g_scan.options.family == AF_INET ? (void *)&ip.addr.ipv4.sin_addr : (void *)&ip.addr.ipv6.sin6_addr, ip_str, sizeof(ip_str));
    if (ft_strcmp(res->ai_canonname, ip_str) != 0)
        sprintf(ip.name, "%s(%s)", res->ai_canonname, ip_str);
    else
        sprintf(ip.name, "%s", ip_str);

    freeaddrinfo(res);
    return ip;
}
