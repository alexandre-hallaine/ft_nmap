#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdbool.h>

#include "functions.h"

t_addr get_interface(sa_family_t family)
{
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1)
		error(1, "getifaddrs: %s\n", strerror(errno));

	t_addr addr = {0};
	for (struct ifaddrs *tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
		if (tmp->ifa_addr->sa_family == family && !(tmp->ifa_flags & IFF_LOOPBACK))
		{
			if (tmp->ifa_addr->sa_family == AF_INET)
				addr.in = ((struct sockaddr_in *)tmp->ifa_addr)->sin_addr;
			else if (tmp->ifa_addr->sa_family == AF_INET6)
				addr.in6 = ((struct sockaddr_in6 *)tmp->ifa_addr)->sin6_addr;
			else
				continue;

			char ip[INET_ADDRSTRLEN | INET6_ADDRSTRLEN] = {0};
			inet_ntop(tmp->ifa_addr->sa_family, &addr, ip, sizeof(ip));
			printf("Using interface %s with address %s\n", tmp->ifa_name, ip);

			break;
		}

	freeifaddrs(ifaddr);
	if (!addr.in.s_addr && !addr.in6.s6_addr)
		error(1, "get_interface: no interface found\n");
	return addr;
}

t_addrinfo get_info(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));

	t_addrinfo addr = {
		.ai_family = res->ai_family,
		.ai_protocol = res->ai_protocol,
		.ai_addrlen = res->ai_addrlen,
	};
	memcpy(&addr.ai_addr, res->ai_addr, res->ai_addrlen);

	char ip[INET_ADDRSTRLEN | INET6_ADDRSTRLEN] = {0};
	inet_ntop(res->ai_family, &res->ai_addr, ip, sizeof(ip));
	printf("Using address %s for host %s\n", ip, res->ai_canonname);

	freeaddrinfo(res);
	return addr;
}
