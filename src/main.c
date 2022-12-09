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

#include "nmap.h"

struct addrinfo *get_ip(char *host)
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

void send_packet(struct addrinfo *res)
{
	char send_buffer[4096] = {0}, recv_buffer[4096] = {0};
	struct tcphdr *tcp_to = (struct tcphdr *)send_buffer;
	int sock = -1, ret = -1;

	// printf("Creating socket with family %d, type %d, protocol %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);
	if ((sock = socket(res->ai_family, SOCK_STREAM, res->ai_protocol)) == -1)
		error(1, "socket: %s\n", strerror(errno));

	// tcp_to->source = htons(80);
	// srand(time(0));
	// tcp_to->dest = htons(rand() % (5000 - 100 + 1) + 100);
	// tcp_to->doff = 5;
	// tcp_to->syn = 1;
	// tcp_to->seq = htonl(0);
	// tcp_to->window = htons(64240);

	if (connect(sock, res->ai_addr, res->ai_addrlen))
		error(1, "connect: %s\n", strerror(errno));

	// printf("\nSending SYN packet to %s:%d\n\n", inet_ntoa(*(struct in_addr *)&((struct sockaddr_in *)res->ai_addr)->sin_addr), ntohs(tcp_to->dest));
	// if (sendto(sock, send_buffer, sizeof(struct tcphdr), 0, res->ai_addr, res->ai_addrlen) < 0)
	// 	error(1, "sendto: %s\n", strerror(errno));

	// while (1)
	// {
	// 	ret = recvfrom(sock, recv_buffer, 4096, 0, 0, 0);
	// 	if (ret < 0)
	// 		error(1, "recvfrom: %s\n", strerror(errno));
	// 	else if (ret == 0)
	// 		error(1, "recvfrom: Connection closed\n");
	// 	else
	// 	{
	// 		struct iphdr *ip_from = (struct iphdr *)recv_buffer;
	// 		struct tcphdr *tcp_from = (struct tcphdr *)(recv_buffer + (ip_from->ihl * 4));

	// 		printf("Received %d bytes from %s:%d\n", ret, inet_ntoa(*(struct in_addr *)&ip_from->saddr), ntohs(tcp_from->source));
	// 		printf("TCP Flags: SYN:%d, ACK:%d, RST:%d\n\n", tcp_to->syn, tcp_to->ack, tcp_to->rst);
	// 		if (tcp_to->dest == tcp_from->source)
	// 		{
	// 			printf("Received correct reply from %s:%d\n", inet_ntoa(*(struct in_addr *)&ip_from->saddr), ntohs(tcp_from->source));
	// 			break;
	// 		}
	// 		else
	// 			printf("%d vs %d, Continue listening\n", ntohs(tcp_to->dest), ntohs(tcp_from->source));
	// 	}
	// }
}

int main(int ac, char **av)
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");

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

	send_packet(res);
	return 0;
}
