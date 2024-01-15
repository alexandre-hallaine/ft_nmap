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
        "\t-h:\t\t\t\tdisplay this help\n"
        "\t-p <ports>:\t\t\tscan the specified ports (default: 1-1024, eg. 1-5,80)\n"
        "\t-s <techniques>:\t\tscan with the specified techniques (default: ASFNXU)\n"
        "\t\t\t\t\tA: ACK, S: SYN, F: FIN, N: NUL, X: XMAS, U: UDP\n"
        "\t-f <file>:\t\t\tscan the specified hosts within the file (<host> not needed)\n"
        "\t-t <threads>:\t\t\tscan with the specified amount of threads (default: 0)\n"
        "\t-6:\t\t\t\tuse IPv6\n"
        "\t-u:\t\t\t\tping host before scanning\n"
        "\t-r:\t\t\t\ttraceroute host before scanning\n"
        "\t-v:\t\t\t\tverbose mode\n"
        "\t-V:\t\t\t\tvery verbose mode\n"
        "\t-m:\t\t\t\tcheck the uptime of the host\n"
        , program);

    error(1, NULL);
}

void parse_thread(char *thread)
{
    if (!is_number(thread))
        error(2, "usage: %s: threads must be a number\n", thread);

    g_scan.options.thread_count = atoi(thread);

    if (g_scan.options.thread_count > 250)
        error(2, "usage: %s: threads execeeding 250\n", thread);
    else if (g_scan.options.thread_count <= 0)
        error(2, "usage: %s: threads must be a number greater than 0\n", thread);
}

void parse_port_range(char *ports) // need to change and send
{
    char *delimiter = ft_strchr(ports, ',');
    int max;

    if (delimiter != NULL)
    {
        parse_port_range(delimiter + 1);
        *delimiter = '\0';
    }

    if (strlen(ports) == 0)
        error(2, "usage: you must specify a port\n");


    delimiter = ft_strchr(ports, '-');
    if (delimiter != NULL)
    {
        if (!is_number(delimiter + 1))
            error(2, "usage: %s: threads must be a number\n", delimiter + 1);

        *delimiter = '\0';
        max = atoi(delimiter + 1);
    }

    if (!is_number(ports))
        error(2, "usage: %s: threads must be a number\n", ports);

    int base = atoi(ports);
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
    {
        if (line[0] != '\0')
        add_IP(get_info(line));
    }

    fclose(fp);
}

void flag_parser(unsigned short *index, char *argv[])
{
    char flag = argv[*index][1];

    if (flag && ft_strchr("psft", flag)) // If the flag is followed by the argument
    {
        (*index)++;
        if (argv[*index] == NULL)
            usage(argv[0]);
    }

    switch (flag)
    {
    case 'h':
        usage(argv[0]);
        break;

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

    case '6':
        g_scan.family = AF_INET6;
        break;

    case 'u':
        g_scan.options.ping = true;
        break;

    case 'r':
        g_scan.options.traceroute = true;
        break;

    case 'v':
        g_scan.options.verbose = 1;
        break;

    case 'V':
        g_scan.options.verbose = 2;
        break;

    case 'm':
        g_scan.options.timestamp = true;
        break;

    default:
        error(2, "usage: %s: invalid option\n", argv[*index]);
        return;
    }
}

void print_stats()
{
    bool first = true;

    printf("Address: ");
    for (t_IP *ip = g_scan.IPs; ip != NULL; ip = ip->next)
    {
        if (first)
            first = false;
        else
            printf(", ");
        printf("%s", ip->destination.name);
    }
    printf("\n");

    printf("Techniques: ");
    for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
        if (g_scan.options.techniques[i])
            printf("%s ", get_technique_name(i));
    printf("\n");

    printf("Thread count: %d\n", g_scan.options.thread_count);

    printf("Port count: ");
    if (!g_scan.options.verbose)
        printf("%d\n", g_scan.options.ports_count);
    else
    {
        first = true;
        int amount = 0;
        for (int i = 0; i <= USHRT_MAX; i++)
            if (g_scan.options.ports[i])
                amount++;
            else if (amount != 0) {
                if (first)
                    first = false;
                else
                    printf(",");
                if (amount == 1)
                    printf("%d", i - 1);
                else if (amount > 1)
                    printf("%d-%d", i - amount, i - 1);
                amount = 0;
            }
        printf("\n");
    }

    printf("\n");
}

void init(int argc, char *argv[])
{
    // Exit if not root
    if (getuid() != 0)
        error(1, "usage: You need to be root to run this program\n");

    // Set default family to IPv4
    g_scan.family = AF_INET;

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
        for (unsigned short i = PORT_MIN; i <= PORT_MAX; i++)
            g_scan.options.ports[i] = true;
        g_scan.options.ports_count = PORT_MAX - PORT_MIN + 1;
    }

    // If -f is not specified, the last argument is the host
    if (g_scan.IPs == NULL)
    {
        if (index != argc - 1)
            usage(argv[0]);
        add_IP(get_info(argv[index]));
    }

    // If the amount of threads is less than the amount of techniques, use the amount of techniques
    // We do this because we assume at least one thread per technique (if threads are used)
    if (g_scan.options.thread_count != 0 && g_scan.options.thread_count < g_scan.options.techniques_count) {
        g_scan.options.thread_count = g_scan.options.techniques_count;
        fprintf(stderr, "Warning: Not enough threads, using %d instead\n\n", g_scan.options.techniques_count);
    }

    // Get interface
    g_scan.interface = get_interface(g_scan.family);

    print_stats();
}
