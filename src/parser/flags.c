#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(char *program)
{
	printf("usage: %s [options] <host>\n", program);

    // should buffer this
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

    // Check if number plz
	g_scan.options.port_min = atoi(port_range);
	g_scan.options.port_max = atoi(delimiter + 1);

	// make error messages more accurate
    if (g_scan.options.port_min <= 0 || g_scan.options.port_max <= 0) // can't be 0 or negative	(negative check unnecessary if properly isnumber before)
        error(2, "usage: %s: invalid port range\n", port_range);
	else if (g_scan.options.port_min >= g_scan.options.port_max) // min must be smaller than max
		error(2, "usage: %s: invalid port range\n", port_range);
    else if (g_scan.options.port_max - g_scan.options.port_min + 1 > 1024) // max - min + 1 must be smaller than 1024 (subject)
        error(2, "usage: %s: port range exceeding 1024\n", port_range);
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
