#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void usage(char *program)
{
	printf("usage: %s [options] <host>\n", program);

	printf("options:\n");
	printf("\t-h:\t\t\tdisplay this help\n");
	printf("\t-s <protocol>:\t\tscan with the specified protocol\n");
	printf("\t\tA: ACK\n");
	printf("\t\tS: SYN\n");
	printf("\t\tF: FIN\n");
	printf("\t\tN: NUL\n");
	printf("\t\tX: XMAS\n");
	printf("\t\tU: UDP\n");
	printf("\t-p <port range>:\tscan the specified port range (default: 1-1024)\n");
	exit(1);
}

void parse_protocol(char *protocol)
{
	for (unsigned char i = 0; i < strlen(protocol); i++)
		switch (protocol[i])
		{
		case 'A':
			g_scan.options.protocol = ACK;
			break;
		case 'S':
			g_scan.options.protocol = SYN;
			break;
		case 'F':
			g_scan.options.protocol = FIN;
			break;
		case 'N':
			g_scan.options.protocol = NUL;
			break;
		case 'X':
			g_scan.options.protocol = XMAS;
			break;
		case 'U':
			g_scan.options.protocol = UDP;
			break;
		default:
			error(2, "usage: %c: invalid protocol\n", protocol[i]);
		}
}

void parse_port_range(char *port_range)
{
	char *delimiter = strchr(port_range, '-');
	if (delimiter == NULL)
		error(2, "usage: %s: invalid port range\n", port_range);

	g_scan.options.port_min = atoi(port_range);
	g_scan.options.port_max = atoi(delimiter + 1);

	if (g_scan.options.port_min > g_scan.options.port_max)
		error(2, "usage: %s: invalid port range\n", port_range);
}

void flag_parser(unsigned short *index, char *argv[])
{
	switch (argv[*index][1])
	{
	case 'h':
		usage(argv[0]);
		break;
	case 's':
		if (argv[*index][2] != '\0' || argv[*index + 1] == NULL)
			usage(argv[0]);
		(*index)++;
		parse_protocol(argv[*index]);
		break;
	case 'p':
		if (argv[*index][2] != '\0' || argv[*index + 1] == NULL)
			usage(argv[0]);
		(*index)++;
		parse_port_range(argv[*index]);
		break;
	default:
		error(2, "usage: %s: invalid option\n", argv[*index]);
	}
}

void command_parser(int argc, char *argv[])
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");

	unsigned short index = 1;
	while (index < argc && argv[index][0] == '-')
	{
		flag_parser(&index, argv);
		index++;
	}

	if (index != argc - 1)
		usage(argv[0]);
	g_scan.destination = get_info(argv[index]);
	g_scan.interface = get_interface(g_scan.destination.family);
}
