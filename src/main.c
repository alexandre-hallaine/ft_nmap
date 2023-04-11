#include "functions.h"

t_scan g_scan = {0};

int main(int argc, char *argv[])
{
	command_parser(argc, argv);
	send_packet(g_scan.options.protocol);

	// receive packet
	{
		// char buffer[65536];
		// struct sockaddr_in source;
		// socklen_t source_len = sizeof(source);
		// while (1)
		// {
		// 	int size = recvfrom(g_data.socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
		// 	if (size == -1)
		// 	{
		// 		if (errno == EAGAIN)
		// 			break;
		// 		error(1, "recvfrom: %s", strerror(errno));
		// 	}

		// char ip[INET_ADDRSTRLEN];
		// inet_ntop(AF_INET, &source.sin_addr, ip, sizeof(ip));
		// printf("Received packet from %s\n", ip);
	}

	// result();
}
