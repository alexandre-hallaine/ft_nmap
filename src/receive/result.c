#include "functions.h"
#include "nmap_services.h"

#include <stdio.h>

char *get_service_name(unsigned short port, bool udp)
{
    if (udp) {
        for (int i = 0; i < amount_tcp; i++)
            if (services_tcp[i].port == port)
                return services_tcp[i].name;
    }
    else
        for (int i = 0; i < amount_udp; i++)
            if (services_udp[i].port == port)
                return services_udp[i].name;
    return "unknown";
}

void print_result()
{
    for (t_IP *ip = g_scan.IPs; ip; ip = ip->next) {
        if (ip->is_down)
            continue;
        char ip_str[INET6_ADDRSTRLEN];
        if (g_scan.family == AF_INET)
            inet_ntop(AF_INET, &ip->destination.addr.in.sin_addr, ip_str, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, &ip->destination.addr.in6.sin6_addr, ip_str, INET6_ADDRSTRLEN);
        printf("\nResults for %s\n", ip_str);

        for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
            if (g_scan.options.techniques[technique]) {
                unsigned short amount[UNFILTERED + 1] = {0};
                t_status default_status = UNSCANNED;

                printf("%s", get_technique_name(technique));
                // Calculate how many times each status appears for this technique
                for (int i = 0; i <= USHRT_MAX; i++)
                    if (g_scan.options.ports[i])
                        amount[ip->status[technique][i]]++;

                //get the default status
                if (g_scan.options.verbose)
                    for (t_status type = 0; type < UNFILTERED + 1; type++)
                        if (amount[type] > amount[default_status])
                            default_status = type;

                int printed = 0;
                for (t_status type = 0; type < UNFILTERED + 1; type++)
                    if ((default_status == UNSCANNED && amount[type] > 30)
                    || (default_status != UNSCANNED && type == default_status)) {
                        printf("\t%d ports on state ", amount[type]);
                        print_status_name(type);

                        printed += amount[type];
                        amount[type] = 0;
                    }

                if (printed == g_scan.options.ports_count)
                    continue;

                printf("\tPORT\tSERVICE\t\tSTATE\n");
                for (int i = 0; i <= USHRT_MAX; i++)
                    if (g_scan.options.ports[i] && amount[ip->status[technique][i]] > 0) {
                        printf("\t%d\t%-15s\t", i, get_service_name(i, technique == UDP));
                        print_status_name(ip->status[technique][i]);
                    }
            }
    }
}
