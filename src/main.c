#include "functions.h"
#include <signal.h>
#include <unistd.h>

t_scan g_scan = {0};

void timeout(int)
{
    pcap_breakloop(g_scan.handle);
}

//void *routine(t_range *range)
//{
//    int scans = (g_scan.options.port_range.max - g_scan.port_range.min);
//    int main_threads = (threads > scans) ? scans : threads % scans ? threads - 1 : threads;
//
//    int padding = scans / threads;
//    int rest = scans % threads;
//    int current_port = g_scan.options.port_min;
//    pthread_t thread[threads];
//    for (int i = 0; i < threads; i++) {
//        if (i == threads - 1 && rest)
//            padding += rest;
//        t_options *options = malloc(sizeof(t_options));
//        options->port_min = current_port;
//        options->port_max = current_port += padding;
//        pthread_create(&thread[i], NULL, routine2, options);
//    }
//
//    for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
//        if (options.techniques[technique]) {
//            printf("Sending packet... (technique: %s)\n", get_technique_name(technique));
//            for (unsigned short port = options.port_min; port <= options.port_max; port += padding)
//                if (port + padding > options.port_max)
//                    send_packet_solo(technique, port, options.port_max);
//                else
//                    send_packet_solo(technique, port, port + padding);
//	}
//}

int main(int argc, char *argv[])
{
    command_parser(argc, argv);

    g_scan.handle = pcap_open_live(NULL, BUFSIZ * 8, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
    struct bpf_program fp;
    pcap_compile(g_scan.handle, &fp, g_scan.filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_scan.handle, &fp);

    if (g_scan.options.thread_count > 1)
        thread_send();

    signal(SIGALRM, timeout);
    alarm(3);
    pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);
    pcap_close(g_scan.handle);

    print_result();
    free_IPs();
}
