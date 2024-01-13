#include "functions.h"
#include <signal.h>
#include <unistd.h>

t_scan g_scan = {0};

void timeout(int)
{
    pcap_breakloop(g_scan.handle);
}

int main(int argc, char *argv[])
{
    command_parser(argc, argv);

    g_scan.handle = pcap_open_live(NULL, BUFSIZ * 8, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
    struct bpf_program fp;
    pcap_compile(g_scan.handle, &fp, g_scan.filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);

    for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
        if (g_scan.options.techniques[i]) {
            send_packet(i);
	    sleep(1);
	}

    signal(SIGALRM, timeout);
    alarm(3);
    pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    pcap_close(g_scan.handle);

    print_result();
}
