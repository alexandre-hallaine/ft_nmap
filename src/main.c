#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <ifaddrs.h>

#include "nmap.h"

struct addrinfo *get_addr(char *host)
{
	struct addrinfo hints = {0}, *res = NULL;
	char *port = "80";

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, port, &hints, &res) != 0)
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
	return NULL;
}

void send_packet(struct addrinfo *res, struct sockaddr_in *host)
{
	char *datagram = calloc(4096, sizeof(char));
	struct tcphdr *tcp_to = (struct tcphdr*)(datagram);
	struct pseudo_header psh = {0};
	int sock = -1;
	
	// create socket
	// printf("Creating socket with family %d, type %d, protocol %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);
	if ((sock = socket(res->ai_family, SOCK_RAW, res->ai_protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	// TCP header configuration
	srand(time(0));
	tcp_to->source = htons(rand() % (5000 - 100 + 1) + 100);
	tcp_to->dest = htons(80);
	tcp_to->seq = htonl(0);
	tcp_to->doff = 10;
	tcp_to->syn = 1;
	tcp_to->window = htons(5840);

	// TCP pseudo header for checksum calculation
	psh.source_address = host->sin_addr.s_addr;
	psh.dest_address = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
	// fill pseudo packet
	char* pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp_to, sizeof(struct tcphdr) + OPT_SIZE);

	// TCP options are only set in the SYN packet
	// ---- set mss ----
	datagram[20] = 0x02;
	datagram[21] = 0x04;
	int16_t mss = htons(48); // mss value
	memcpy(datagram + 22, &mss, sizeof(int16_t));
	// ---- enable SACK ----
	datagram[24] = 0x04;
	datagram[25] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;

	tcp_to->check = checksum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE);

	printf("\nSending SYN packet to %s:%d\n\n", inet_ntoa(*(struct in_addr *)&((struct sockaddr_in *)res->ai_addr)->sin_addr), ntohs(tcp_to->dest));
	if (sendto(sock, datagram, sizeof(struct tcphdr) + OPT_SIZE, 0, res->ai_addr, res->ai_addrlen) < 0)
		error(1, "sendto: %s\n", strerror(errno));
}

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");

	if (!av[1] || ac != 2)
		error(1, "usage: %s <host>", av[0]);

	char ip[INET6_ADDRSTRLEN];
	struct addrinfo *res = get_addr(av[1]);
	struct sockaddr_in *host = get_ifaddr();
	if (!host)
		error(1, "get_ifaddr: Interface not found\n");

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6)
        	inet_ntop(p->ai_family, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, ip, sizeof(ip));
		else
			inet_ntop(p->ai_family, &((struct sockaddr_in *)p->ai_addr)->sin_addr, ip, sizeof(ip));
        printf("%s with IPV%d: %s\n", av[1], p->ai_family == AF_INET ? 4 : 6, ip);
    }

	send_packet(res, host);
	return 0;
}
