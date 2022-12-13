#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>

#include "functions.h"
#include "nmap.h"

struct addrinfo *get_addr(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));
	return res;
}

struct sockaddr_in *get_ifaddr()
{
	struct ifaddrs *addrs = NULL, *tmp = NULL;
	if (getifaddrs(&addrs) == -1)
		error(1, "getifaddrs: %s\n", strerror(errno));
	for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET && ft_strcmp(tmp->ifa_name, "eth0") == 0)
		{
			struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
			freeifaddrs(addrs);
			return pAddr;
		}
	}
	freeifaddrs(addrs);
	error(1, "get_ifaddr: Interface not found\n");
	return NULL;
}

void create_socket()
{
	// create socket
	// printf("Creating socket with family %d, type %d, protocol %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);
	if ((g_data.sock = socket(g_data.res->ai_family, SOCK_RAW, g_data.res->ai_protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	// socket options
	struct timeval timeout = {(long)0, 500000};
	if (setsockopt(g_data.sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		error(1, "setsockopt: %s\n", strerror(errno));
}
