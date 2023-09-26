#include "functions.h"

#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>

t_addr get_interface(int family)
{
    // needs some comments (not chatgpt :) )
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1)
		error(1, "getifaddrs: %s\n", strerror(errno));

	t_addr addr = {0};
	struct ifaddrs *tmp = NULL;
	for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
		if ((tmp->ifa_flags & IFF_BROADCAST) && tmp->ifa_addr->sa_family == family) // ifa_addr always exists if IFF_BROADCAST is set
		{
			if (family == AF_INET)
				addr.in = *(struct sockaddr_in *)tmp->ifa_addr;
			else if (family == AF_INET6)
				addr.in6 = *(struct sockaddr_in6 *)tmp->ifa_addr;
			else
				continue;

			{
				char ip[INET6_ADDRSTRLEN] = {0};
				inet_ntop(family, family == AF_INET ? (void *)&addr.in.sin_addr : (void *)&addr.in6.sin6_addr, ip, sizeof(ip));
				printf("Using interface %s with address %s\n", tmp->ifa_name, ip);
			}

			break;
		}

	freeifaddrs(ifaddr);
	if (tmp == NULL)
		error(1, "get_interface: no interface found\n");
	return addr;
}

t_addrinfo get_info(char *host)
{
    // needs some comments (not chatgpt :) )
	struct addrinfo *res, hints = {.ai_flags = AI_CANONNAME};
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));

	char ip[INET6_ADDRSTRLEN] = {0};
	if (res->ai_family == AF_INET)
		inet_ntop(res->ai_family, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof(ip));
	else if (res->ai_family == AF_INET6)
		inet_ntop(res->ai_family, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, ip, sizeof(ip));
	else
		error(1, "get_info: unknown address family\n");
	printf("Using host %s with address %s\n", res->ai_canonname, ip);

	t_addrinfo addr = {
		.family = res->ai_family,
		.addrlen = res->ai_addrlen,
	};
	memcpy(&addr.addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return addr;
}
