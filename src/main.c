#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include "nmap.h"

struct addrinfo *get_ip(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));
	return res;
}

int main(int ac, char **av)
{
	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);

	char ip[INET6_ADDRSTRLEN];
	struct addrinfo *res = get_ip(av[1]);
	for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6)
        	inet_ntop(p->ai_family, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, ip, sizeof(ip));
		else
			inet_ntop(p->ai_family, &((struct sockaddr_in *)p->ai_addr)->sin_addr, ip, sizeof(ip));
        printf("%s with IPV%d: %s\n", av[1], p->ai_family == AF_INET ? 4 : 6, ip);
    }
	return 0;
}