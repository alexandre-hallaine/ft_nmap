#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "functions.h"

uint32_t get_interface(int family)
{
	struct ifaddrs *ifaddr;
	uint32_t ret = 0;

	if (getifaddrs(&ifaddr) == -1)
		error(1, "getifaddrs: %s\n", strerror(errno));

	for (struct ifaddrs *tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
	{
		if (tmp->ifa_flags & IFF_LOOPBACK)
			continue;
		if (tmp->ifa_addr->sa_family != family)
			continue;

		if (family == AF_INET)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)tmp->ifa_addr;
			ret = addr->sin_addr.s_addr;
			// printf("Interface: %s, address: %s\n", tmp->ifa_name, inet_ntoa(addr->sin_addr));
			break;
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

t_addrinfo get_info(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));

	t_addrinfo ret = {
		.ai_family = res->ai_family,
		.ai_protocol = res->ai_protocol,
		.ai_addrlen = res->ai_addrlen,
	};
	memcpy(&ret.ai_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return ret;
}
