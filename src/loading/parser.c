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
	printf("\t-p <port min>-<port max>:\tscan the specified port range (default: 1-1024)\n");
	printf("\t-s <techniques>:\t\tscan with specified techniques (eg: '-s AS' for ACK and SYN)\n");
	printf("\t\tA: ACK\n");
	printf("\t\tS: SYN\n");
	printf("\t\tF: FIN\n");
	printf("\t\tN: NUL\n");
	printf("\t\tX: XMAS\n");
	printf("\t\tU: UDP\n");
	exit(1);
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

void parse_technique(char *technique)
{
	for (unsigned char i = 0; i < strlen(technique); i++)
		switch (technique[i])
		{
		case 'A':
			g_scan.options.techniques[ACK] = true;
			break;
		case 'S':
			g_scan.options.techniques[SYN] = true;
			break;
		case 'F':
			g_scan.options.techniques[FIN] = true;
			break;
		case 'N':
			g_scan.options.techniques[NUL] = true;
			break;
		case 'X':
			g_scan.options.techniques[XMAS] = true;
			break;
		case 'U':
			g_scan.options.techniques[UDP] = true;
			break;

		default:
			error(2, "usage: %c: unknown technique\n", technique[i]);
		}
}

void flag_parser(unsigned short *index, char *argv[])
{
	if (argv[*index][2] != '\0') // use -h instead of -help
		error(2, "usage: %s: invalid option\n", argv[*index]);

	switch (argv[*index][1])
	{
	case 'h':
		usage(argv[0]);
		break;

	case 'p':
		(*index)++;
		if (argv[*index] == NULL)
			usage(argv[0]);

		parse_port_range(argv[*index]);
		break;

	case 's':
		(*index)++;
		if (argv[*index] == NULL)
			usage(argv[0]);

		parse_technique(argv[*index]);
		break;

	default:
		error(2, "usage: %s: invalid option\n", argv[*index]);
	}
}

void command_parser(int argc, char *argv[])
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");

	g_scan.options.port_min = 1;
	g_scan.options.port_max = 1024;

	unsigned short index = 1;
	while (index < argc && argv[index][0] == '-')
	{
		flag_parser(&index, argv);
		index++;
	}

	// if no technique is specified, scan with all of them
	{
		bool technique_specified = false;
		for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
			if (g_scan.options.techniques[i])
				technique_specified = true;

		if (!technique_specified)
			for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
				g_scan.options.techniques[i] = true;
	}

	if (index != argc - 1)
		usage(argv[0]);
	g_scan.destination = get_info(argv[index]);
	g_scan.interface = get_interface(g_scan.destination.family);
}
