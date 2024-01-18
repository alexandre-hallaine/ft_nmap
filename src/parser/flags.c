#include "functions.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
             "\n"
             "arguments:\n"
             "\t<host>:\t\t\t\thost to scan\n", program);
    exit(0);
}

int get_number(char *str)
{
    if (ft_strlen(str) == 0)
        error(2, "get_number: empty string\n");
    else if (!is_number(str))
        error(2, "get_number: %s: not a number\n", str);
    return ft_atoi(str);
}

void parse_thread(char *number)
{
    g_scan.options.thread_count = get_number(number);
    if (g_scan.options.thread_count > 250)
        error(2, "thread: %s: number must be less or equal to 250\n", number);
    else if (g_scan.options.thread_count <= 0)
        error(2, "thread: %s: number must be greater than 0\n", number);
}

void parse_port_range(char *range) // need to change and send
{
    int base, max;
    char *delimiter = ft_strchr(range, ',');

    if (delimiter != NULL)
    {
        *delimiter = '\0';
        parse_port_range(delimiter + 1);
    }

    if (ft_strlen(range) == 0)
        error(2, "port: you must specify a port\n");

    delimiter = ft_strchr(range, '-');
    if (delimiter != NULL)
    {
        *delimiter = '\0';
        max = get_number(delimiter + 1);
    }

    base = get_number(range);
    if (base < 0 || base > 65535)
        error(2, "port: %d: invalid port\n", base);
    else if (delimiter == NULL)
        g_scan.options.port[base] = true;
    else if (max < 0 || max > USHRT_MAX)
        error(2, "port: %d: invalid port\n", max);
    else if (base > max)
        error(2, "port: %d-%d: min port must be less than max port\n", base, max);
    else
        for (int i = base; i <= max; i++)
            g_scan.options.port[i] = true;

    int amount = 0;
    for (int i = 0; i <= USHRT_MAX; i++)
        if (g_scan.options.port[i])
            amount++;

    if (amount > 1024)
        error(2, "port: you can't scan more than 1024 ports\n");
    g_scan.options.port_count = amount;
}

void parse_technique(char *technique)
{
    for (int i = 0; i < ft_strlen(technique); i++)
    {
        switch (technique[i])
        {
            case 'A':
                g_scan.options.technique[ACK] = true;
                break;
            case 'S':
                g_scan.options.technique[SYN] = true;
                break;
            case 'F':
                g_scan.options.technique[FIN] = true;
                break;
            case 'N':
                g_scan.options.technique[NUL] = true;
                break;
            case 'X':
                g_scan.options.technique[XMAS] = true;
                break;
            case 'U':
                g_scan.options.technique[UDP] = true;
                break;
            default:
                error(2, "technique: %c: unknown technique\n", technique[i]);
        }

        g_scan.options.technique_count++;
    }
}

void parse_file(char *file)
{
    char *line;
    FILE *fp = fopen(file, "r");

    if (fp == NULL)
        error(2, "fopen: %s\n", strerror(errno));

    // Read file line by line and add IP to list
    while (get_next_line(fp->_fileno, &line) > 0)
    {
        if (line[0] != '\0')
            add_IP(get_ip(line));
        free(line);
    }
    free(line);

    fclose(fp);
}
