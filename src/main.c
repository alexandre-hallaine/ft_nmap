#include "functions.h"
#include "traceroute.h"

#include <signal.h>
#include <unistd.h>

t_scan g_scan = {0};

void timeout()
{
    pcap_breakloop(g_scan.handle);
    g_scan.stop_pcap = true;
}

int main(int argc, char *argv[])
{
    init(argc, argv);

    if (g_scan.options.ping)
        traceroute(PING);
    check_down();
    if (g_scan.options.traceroute)
        traceroute(TRACEROUTE);
    check_down();
    if (g_scan.options.timestamp)
        traceroute(TIMESTAMP);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    init_send();

    printf("Waiting for responses...\n");
    signal(SIGALRM, timeout);
    // In case of no response, stop the scan after 30 seconds
    alarm(15);
    while (!g_scan.stop_pcap) {
        pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    }
    if (g_scan.options.verbose)
        printf("\n");

    pcap_close(g_scan.handle);

    print_result();
    print_time(tv);

    free_IPs();
    return(0);
}
