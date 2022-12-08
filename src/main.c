#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(int ac, char **av)
{
	int ret = 0;
	int sd = -1;
	char *port = "80";
	//char *port = NULL;

	struct hostent		*h;

	if (!av[1] || ac != 2)
	{
		printf("Usage: %s <host>\n", av[0]);
		return (1);
	}

	struct addrinfo hints = {0}, *res;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	h = gethostbyname(av[1]);
	// print list of ip addresses from gethostbyname
	for (int i = 0; h->h_addr_list[i]; i++)
	{
		struct in_addr addr;
		memcpy(&addr, h->h_addr_list[i], sizeof(struct in_addr));
		printf("gethostbyname: %s\n", inet_ntoa(addr));
	}

	ret = getaddrinfo(av[1], port, &hints, &res);
	if (ret)
	{
		printf("getaddrinfo: %s\n", gai_strerror(ret));
		return (1);
	}

	 for(struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next)
    {
		char ip[NI_MAXHOST];
		inet_ntop(AF_INET, &addr->ai_addr, ip, sizeof(ip));

        sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sd == -1)
		{
			printf("socket: %s\n", strerror(errno));
			return (1);
		}

		printf("CONNECTING TO %s: %s\n", av[1], ip);
        connect(sd, addr->ai_addr, addr->ai_addrlen);
		printf("CONNECTED TO %s: %s\n", av[1], ip);

		fprintf(stderr, "%s: %s\n", av[1], strerror(errno));
		printf("\n");
        close(sd);
        sd = -1;
    }

    freeaddrinfo(res);
	
	return 0;
}