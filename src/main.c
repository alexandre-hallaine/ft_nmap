#include "functions.h"
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

t_scan g_scan = {0};

void timeout(int)
{
    pcap_breakloop(g_scan.handle);
    g_scan.stop = true;
}

int main(int argc, char *argv[])
{
    init(argc, argv);

    g_scan.handle = pcap_open_live(NULL, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
    struct bpf_program fp = {0};
    pcap_compile(g_scan.handle, &fp, g_scan.filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);

    if (g_scan.options.thread_count > 1)
        thread_send();
    else for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (g_scan.options.techniques[technique])
        {
            t_options *options = malloc(sizeof(t_options));
            ft_memcpy(options, &g_scan.options, sizeof(t_options));
            routine(options);
            sleep(1);
        }

    signal(SIGALRM, timeout);
    g_scan.stop = false;
    while (!g_scan.stop) {
        alarm(2);
        pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    }

    pcap_close(g_scan.handle);
    print_result();
    free_IPs();
}
