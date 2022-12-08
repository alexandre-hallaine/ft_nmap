#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include "nmap.h"

struct addrinfo get_ip(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		error(1, "getaddrinfo: %s\n", gai_strerror(errno));
	return *res;
}

int main(int ac, char **av)
{
	if (!av[1] || ac != 2) error(1, "usage: %s <host>", av[0]);

	struct addrinfo res = get_ip(av[1]);
	char *ip = inet_ntoa(((struct sockaddr_in *)res.ai_addr)->sin_addr);
	printf("%s\n", ip);
	return 0;
}