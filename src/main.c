#include "functions.h"
#include <signal.h>
#include <unistd.h>

t_scan g_scan = {0};

void timeout(int)
{
    pcap_breakloop(g_scan.handle);
    g_scan.stop = true;
}

int main(int argc, char *argv[])
{
    command_parser(argc, argv);

    g_scan.handle = pcap_open_live(NULL, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
    struct bpf_program fp;
    pcap_compile(g_scan.handle, &fp, g_scan.filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);

    if (g_scan.options.thread_count > 1)
        thread_send();

    signal(SIGALRM, timeout);
    g_scan.stop = false;
    while (!g_scan.stop) {
        alarm(1);
        pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    }

    pcap_close(g_scan.handle);
    print_result();
    free_IPs();
}
