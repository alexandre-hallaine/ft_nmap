#include "functions.h"

#include <unistd.h>
#include <stdlib.h>

void print_stats()
{
    printf("Address: ");
    for (t_IP *ip = g_scan.ip; ip != NULL; ip = ip->next)
        printf("%s ", ip->name);
    printf("\n");

    printf("Techniques: ");
    for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
        if (g_scan.options.technique[i])
            printf("%s ", get_technique_name(i));
    printf("\n");

    printf("Thread count: %d\n", g_scan.options.thread_count);

    printf("Port count: ");
    if (!g_scan.options.verbose)
        printf("%d\n", g_scan.options.port_count);
    else
    {
        bool first = true;
        int amount = 0;
        for (int i = 0; i <= USHRT_MAX; i++)
            if (g_scan.options.port[i])
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
    g_scan.options.family = AF_INET;

    // Parse flags
    unsigned short index;
    for (index = 1; index < argc && argv[index][0] == '-'; index++)
        flag_parser(&index, argv);

    if (g_scan.ip == NULL)
    {
        // If the last argument exists
        if (index != argc - 1)
            usage(argv[0]);

        if (g_scan.options.file)
            parse_file(argv[index]);
        else
            add_IP(get_ip(argv[index]));
    }

    // Get interface
    g_scan.interface = get_interface();

    // If no techniques specified, scan all
    if (g_scan.options.technique_count == 0)
    {
        for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
            g_scan.options.technique[i] = true;
        g_scan.options.technique_count = TECHNIQUE_COUNT;
    }

    // If no port range specified, scan 1-1024
    if (g_scan.options.port_count == 0)
    {
        for (unsigned short i = PORT_MIN; i <= PORT_MAX; i++)
            g_scan.options.port[i] = true;
        g_scan.options.port_count = PORT_MAX - PORT_MIN + 1;
    }

    // If the amount of threads is less than the amount of techniques, use the amount of techniques
    // We do this because we assume at least one thread per technique (if threads are used)
    if (g_scan.options.thread_count != 0 && g_scan.options.thread_count < g_scan.options.technique_count) {
        g_scan.options.thread_count = g_scan.options.technique_count;
        fprintf(stderr, "Warning: Not enough threads, using %d instead\n\n", g_scan.options.thread_count);
    }
    if (g_scan.options.thread_count > g_scan.options.port_count * g_scan.options.technique_count) {
        g_scan.options.thread_count = g_scan.options.port_count * g_scan.options.technique_count;
        fprintf(stderr, "Warning: Too many threads, using %d instead\n\n", g_scan.options.thread_count);
    }

    g_scan.handle = pcap_open_live(NULL, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);

    char filter[BUFSIZ] = {0};
    for (t_IP *ip = g_scan.ip; ip != NULL; ip = ip->next)
    {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        inet_ntop(g_scan.options.family, g_scan.options.family == AF_INET ? (void *)&ip->addr.ipv4.sin_addr : (void *)&ip->addr.ipv6.sin6_addr, ip_str, sizeof(ip_str));

        ft_strcat(filter, "host ");
        ft_strcat(filter, ip_str);
        if (ip->next)
            ft_strcat(filter, " or ");
    }
    printf("Filter: %s\n", filter);

    struct bpf_program fp = {0};
    pcap_compile(g_scan.handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);
    free(fp.bf_insns);

    print_stats();
}
