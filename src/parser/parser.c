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

void parse_port_range(char *ports) // need to change and send
{
    char *delimiter = strchr(ports, ',');
    int base = atoi(ports);
    int max;

    if (delimiter != NULL)
    {
        parse_port_range(delimiter + 1);
        *delimiter = '\0';
    }

    if (strlen(ports) == 0)
        error(2, "usage: you must specify a port\n");

    delimiter = strchr(ports, '-');
    if (delimiter != NULL)
        max = atoi(delimiter + 1);

    if (base < 0 || base > 65535)
        error(2, "usage: %d: invalid port\n", base);
    else if (delimiter == NULL)
        g_scan.options.ports[base] = true;
    else if (max < 0 || max > USHRT_MAX)
        error(2, "usage: %d: invalid port\n", max);
    else if (base > max)
        error(2, "usage: %d-%d: min port must be less than max port\n", base, max);
    else
        for (int i = base; i <= max; i++)
            g_scan.options.ports[i] = true;

    int amount = 0;
    for (int i = 0; i <= USHRT_MAX; i++)
        if (g_scan.options.ports[i])
            amount++;

    if (amount > 1024)
        error(2, "usage: %s: port range exceeding 1024\n", ports);
    g_scan.options.ports_count = amount;
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
    char *line;
    FILE *fp = fopen(file, "r");
    if (fp == NULL)
        error(2, "usage: %s: file not found\n", file);

    // Read file line by line and add IP to list
    while (get_next_line(fp->_fileno, &line) > 0)
        add_IP(get_info(line));

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
    if (g_scan.options.ports_count == 0)
    {
        for (unsigned short i = 1; i <= 1024; i++)
            g_scan.options.ports[i] = true;
        g_scan.options.ports_count = 1024;
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
