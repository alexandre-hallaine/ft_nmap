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
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1)
		error(1, "getifaddrs: %s\n", strerror(errno));

	t_addr addr = {0};
	bool found = false;
	for (struct ifaddrs *tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
		if (tmp->ifa_addr->sa_family == family && !(tmp->ifa_flags & IFF_LOOPBACK))
		{
			if (tmp->ifa_addr->sa_family == AF_INET)
				addr.in = *(struct sockaddr_in *)tmp->ifa_addr;
			else if (tmp->ifa_addr->sa_family == AF_INET6)
				addr.in6 = *(struct sockaddr_in6 *)tmp->ifa_addr;
			else
				continue;

			char ip[INET6_ADDRSTRLEN] = {0};
			if (tmp->ifa_addr->sa_family == AF_INET)
				inet_ntop(tmp->ifa_addr->sa_family, &addr.in.sin_addr, ip, sizeof(ip));
			else if (tmp->ifa_addr->sa_family == AF_INET6)
				inet_ntop(tmp->ifa_addr->sa_family, &addr.in6.sin6_addr, ip, sizeof(ip));
			printf("Using interface %s with address %s\n", tmp->ifa_name, ip);

			found = true;
			break;
		}

	if (!found)
		error(1, "get_interface: no interface found\n");

	freeifaddrs(ifaddr);
	return addr;
}

t_addrinfo get_info(char *host)
{
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
		.protocol = res->ai_protocol,
		.addrlen = res->ai_addrlen,
	};
	memcpy(&addr.addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return addr;
}
