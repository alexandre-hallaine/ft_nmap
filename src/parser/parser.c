#include "functions.h"

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void usage(char *program)
{
    printf("usage: %s [options] <host>\n"
        "options:\n"
        "\t-h:\t\t\tdisplay this help\n"
        "\t-f <file>:\t\tscan the specified file\n"
        "\t-t <threads>:\t\tscan with specified threads (default: 0)\n"
        "\t-p <port min>-<port max>:\tscan the specified port range (default: 1-1024)\n"
        "\t-s <techniques>:\t\tscan with specified techniques (eg: '-s AS' for ACK and SYN)\n"
        "\t\tA: ACK\n"
        "\t\tS: SYN\n"
        "\t\tF: FIN\n"
        "\t\tN: NUL\n"
        "\t\tX: XMAS\n"
        "\t\tU: UDP\n", program);

	error(1, NULL);
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

void parse_port_range(char *port_range) // need to change and send
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
    {
        g_scan.options.techniques_count++;

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
}

void parse_file(char *file)
{
    FILE *fp = fopen(file, "r");
    if (fp == NULL)
        error(2, "usage: %s: file not found\n", file);

    // Domain names can be up to 253 characters in length hence the UCHAR_MAX
    char line[UCHAR_MAX] = {0};

    while (fgets(line, sizeof(line), fp) != NULL) // switch to GNL
    {
        char *newline = strchr(line, '\n');
        // No point in continuing if the line is too long since it will not be a valid domain name or IP
        if (newline == NULL)
            line[sizeof(line) - 1] = '\0';
        else
            *newline = '\0';

        // Add the IP to the list
        add_IP(get_info(line));
    }

    fclose(fp);
}

void flag_parser(unsigned short *index, char *argv[])
{
    char flag = argv[*index][1];
    char flags[] = "psft";

    if (flag == 'h')
        usage(argv[0]);

    if (flag && strchr(flags, flag) == NULL)
        error(2, "usage: %s: invalid option\n", argv[*index]);

    (*index)++;
    if (argv[*index] == NULL)
        usage(argv[0]);
    else
        switch (flag)
        {
        case 'p':
            parse_port_range(argv[*index]);
            break;

        case 's':
            parse_technique(argv[*index]);
            break;

        case 'f':
            parse_file(argv[*index]);
            break;

        case 't':
            parse_thread(argv[*index]);
            break;
        }
}

void init(int argc, char *argv[])
{
    // Exit if not root
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n");

    // Parse flags
    unsigned short index;
    for (index = 1; index < argc && argv[index][0] == '-'; index++)
        flag_parser(&index, argv);

    // If no techniques specified, scan all
    if (g_scan.options.techniques_count == 0)
    {
        memset(g_scan.options.techniques, true, TECHNIQUE_COUNT);
        g_scan.options.techniques_count = TECHNIQUE_COUNT;
    }

    // If no port range specified, scan 1-1024
    if (g_scan.options.port_range.max == 0)
    {
        g_scan.options.port_range.min = 1;
        g_scan.options.port_range.max = 1024;
    }

    // If the amount of threads is less than the amount of techniques, use the amount of techniques
    // We do this because we assume at least one thread per technique (if threads are used)
    if (g_scan.options.thread_count != 0 && g_scan.options.thread_count < g_scan.options.techniques_count) {
        g_scan.options.thread_count = g_scan.options.techniques_count;
        printf("Warning: Not enough threads, using %d instead\n", g_scan.options.techniques_count);
    }

    // If -f is not specified, the last argument is the host
    if (g_scan.IPs == NULL)
    {
        if (index != argc - 1)
            usage(argv[0]);
        add_IP(get_info(argv[index]));
    }

    // Get interface
    g_scan.interface = get_interface(g_scan.family);
}
