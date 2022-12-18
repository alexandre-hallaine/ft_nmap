#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "functions.h"

uint32_t get_interface_addr(int family)
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
			printf("Interface: %s, address: %s\n", tmp->ifa_name, inet_ntoa(addr->sin_addr));
			break;
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

struct addrinfo get_addr(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));

	struct addrinfo ret = {0};
	memcpy(&ret, res, sizeof(struct addrinfo));
	freeaddrinfo(res);
	return ret;
}

void create_socket()
{
	if ((g_data.socket = socket(g_data.destination.ai_family, SOCK_RAW, g_data.destination.ai_protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	struct timeval timeout = {(long)0, 100000};
	if (setsockopt(g_data.socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		error(1, "setsockopt: %s\n", strerror(errno));
}

unsigned short tcp_checksum(struct data data)
{
	struct ipv4_pseudo_header pseudo_header = {
		.source_address = g_data.source_ip,
		.destination_address = ((struct sockaddr_in *)g_data.destination.ai_addr)->sin_addr.s_addr,
		.protocol = IPPROTO_TCP,
		.tcp_length = htons(sizeof(struct data))
	};

	data.tcp.check = 0;
	
	char buffer[sizeof(struct ipv4_pseudo_header) + sizeof(data)];
	memcpy(buffer, &pseudo_header, sizeof(struct ipv4_pseudo_header));
	memcpy(buffer + sizeof(struct ipv4_pseudo_header), &data, sizeof(data));

	return checksum((unsigned short *)buffer, sizeof(buffer));
}
