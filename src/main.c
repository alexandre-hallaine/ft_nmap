#include "functions.h"
#include "traceroute.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

t_scan g_scan = {0};

void timeout()
{
    pcap_breakloop(g_scan.handle);
    g_scan.stop = true;
}

void check_down()
{
    bool all_down = true;
    for (t_IP *IP = g_scan.IPs; IP != NULL; IP = IP->next)
        if (!IP->is_down)
        {
            all_down = false;
            break;
        }

    if (all_down)
        error(1, "None of the hosts specified are up. Stopping now.\n");
}

int main(int argc, char *argv[])
{
    init(argc, argv);

    if (g_scan.options.ping)
    {
        printf("Starting ping...\n");
        traceroute(PING);
        check_down();
    }

    if (g_scan.options.traceroute)
    {
        printf("Starting traceroute...\n");
        traceroute(TRACEROUTE);
        check_down();
    }

    if (g_scan.options.timestamp)
    {
        printf("Starting timestamp...\n");
        traceroute(TIMESTAMP);
    }

    g_scan.handle = pcap_open_live(NULL, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
    struct bpf_program fp = {0};
    pcap_compile(g_scan.handle, &fp, g_scan.filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    printf("Sending packets...\n");
    if (g_scan.options.thread_count > 1)
        thread_send();
    else {
        for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
            if (g_scan.options.techniques[technique])
            {
                if (g_scan.options.verbose)
                {
                    printf("%s... ", get_technique_name(technique));
                    fflush(stdout);
                }

                t_options *options = ft_calloc(1, sizeof(t_options));
                if (!options)
                    error(1, "main: ft_calloc failed\n");
                ft_memcpy(options, &g_scan.options, sizeof(t_options));
                for (t_technique i = 0; i < TECHNIQUE_COUNT; i++)
                    options->techniques[i] = false;
                options->techniques[technique] = true;
                routine(options);
            }
        if (g_scan.options.verbose)
            printf("\n");
    }

    printf("Waiting for responses...\n");
    signal(SIGALRM, timeout);
    // In case of no response, stop the scan after 30 seconds
    alarm(15);
    g_scan.stop = false;
    while (!g_scan.stop) {
        pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    }
    if (g_scan.options.verbose)
        printf("\n");

    struct timeval tv2;
    gettimeofday(&tv2, NULL);
    double time = (tv2.tv_sec - tv.tv_sec) + (tv2.tv_usec - tv.tv_usec) / 1000000.0;
    printf("\nScan finished in %.2f seconds\n", time);

    pcap_close(g_scan.handle);
    print_result();
    free_IPs();
    free(fp.bf_insns);
}
