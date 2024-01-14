#include "functions.h"

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void usage(char *program)
{
	printf("usage: %s [options] <host>\n", program);

    // should buffer this
	printf("options:\n");
	printf("\t-h:\t\t\tdisplay this help\n");
    printf("\t-f <file>:\t\tscan the specified file\n");
    printf("\t-t <threads>:\t\tscan with specified threads (default: 0)\n");
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

void parse_thread(char *thread)
{
    // Check if number plz
	g_scan.options.thread_count = atoi(thread);

    if (g_scan.options.thread_count > 250)
        error(2, "usage: %s: threads execeeding 250\n", thread);
    else if (g_scan.options.thread_count <= 0)
        error(2, "usage: %s: threads must be a number greater than 0\n", thread);
}

void parse_port_range(char *port_range)
{
	char *delimiter = strchr(port_range, '-');
	if (delimiter == NULL)
		error(2, "usage: %s: invalid port range\n", port_range);

    // Check if number plz
	g_scan.options.port_range.min = atoi(port_range);
	g_scan.options.port_range.max = atoi(delimiter + 1);

	// make error messages more accurate
    if (g_scan.options.port_range.min <= 0 || g_scan.options.port_range.max <= 0) // can't be 0 or negative	(negative check unnecessary if properly isnumber before)
        error(2, "usage: %s: invalid port range\n", port_range);
	else if (g_scan.options.port_range.min >= g_scan.options.port_range.max) // min must be smaller than max
		error(2, "usage: %s: invalid port range\n", port_range);
    else if (g_scan.options.port_range.max - g_scan.options.port_range.min + 1 > 1024) // max - min + 1 must be smaller than 1024 (subject)
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

void parse_file(char *file)
{
    FILE *fp = fopen(file, "r");
    if (fp == NULL)
        error(2, "usage: %s: file not found\n", file);

    char line[1024] = {0};
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char *newline = strchr(line, '\n');
        if (newline != NULL)
            *newline = '\0';

        add_IP(get_info(line));
    }

    fclose(fp);
}

void flag_parser(unsigned short *index, char *argv[])
{
	// may need to be modified when more options are added
	if (argv[*index][2] != '\0') // use -h instead of -help
		error(2, "usage: %s: invalid option\n", argv[*index]);

	switch (argv[*index][1]) // repeated code perhaps we can figure out a way to make this more efficient (make shit fall into h ?)
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
		// bool check here
		break;

    case 't':
        (*index)++;
        if (argv[*index] == NULL)
            usage(argv[0]);

        parse_thread(argv[*index]);
        break;

    case 'f':
        (*index)++;
        if (argv[*index] == NULL)
            usage(argv[0]);

        parse_file(argv[*index]);
        break;


	default:
		error(2, "usage: %s: invalid option\n", argv[*index]);
	}
}

// naming
void command_parser(int argc, char *argv[])
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n"); // move to main

	g_scan.options.port_range.min = 1;
	g_scan.options.port_range.max = 1024; // change with define

	unsigned short index = 1; // for loop is better ?
	while (index < argc && argv[index][0] == '-')
	{
		flag_parser(&index, argv);
		index++;
	}

	// if no technique is specified, scan with all of them
    // remove block
	{
        int techniques = 0;
        for (int i = 0; i < TECHNIQUE_COUNT; i++)
            if (g_scan.options.techniques[i])
                techniques++;

        if (techniques == 0)
        {
            memset(g_scan.options.techniques, true, TECHNIQUE_COUNT);
            techniques = TECHNIQUE_COUNT;
        }

        if (g_scan.options.thread_count != 0 && g_scan.options.thread_count < techniques) {
            g_scan.options.thread_count = techniques;
            printf("Warning: too less threads, using %d instead\n", techniques);
        }
	}

    // I feel like this should be done before the flags
    if (g_scan.IPs == NULL)
    {
        if (g_scan.IPs == NULL && index != argc - 1)
            usage(argv[0]);
        add_IP(get_info(argv[index]));
    }

    g_scan.interface = get_interface(g_scan.family);
}
