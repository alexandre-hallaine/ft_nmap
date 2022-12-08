#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

int main(int ac, char **av)
{
	int ret = 0;

	if (!av[1] || ac != 2)
	{
		printf("Usage: %s <host>\n", av[0]);
		return (1);
	}

	struct addrinfo hints = {0}, *res;
	hints.ai_family = AF_INET;
	//hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(av[1], NULL, &hints, &res);
	if (ret)
	{
		printf("getaddrinfo: %s\n", gai_strerror(ret));
		return (1);
	}

	for (struct addrinfo *p = res; p; p = p->ai_next)
	{
		char ip[NI_MAXHOST];
		inet_ntop(AF_INET, &p->ai_addr, ip, sizeof(ip));
		printf("%s\n", ip);
	}
	
	return 0;
}