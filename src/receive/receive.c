#include "functions.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void timeout(int sig)
{
	(void)sig;
	g_scan.timeout = true;
}

void receive_packet(t_protocol protocol)
{
	(void)protocol;

	g_scan.timeout = false;
	signal(SIGALRM, timeout);
	alarm(1); // 1 second timeout

	t_packet buffer;
	t_addr source;
	socklen_t source_len = sizeof(source);

	while (!g_scan.timeout)
	{
		if (recvfrom(g_scan.socket, &buffer, sizeof(buffer), 0, &source.addr, &source_len) == -1)
			error(1, "recvfrom: %s\n", strerror(errno));
		if (memcmp(&source.addr, &g_scan.destination.addr, source_len))
			continue;

		printf("Packet received!\n");
	}
}
