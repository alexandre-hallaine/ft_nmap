#include "functions.h"

#include <stdio.h>

void print_result()
{
    for (t_IP *ip = g_scan.IPs; ip; ip = ip->next) {
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

                printf("\nResults for technique: %s\n", get_technique_name(technique));
                // Calculate how many times each status appears for this technique
                for (unsigned short index = g_scan.options.port_range.min;
                     index <= g_scan.options.port_range.max; index++)
                    amount[ip->status[technique][index]]++;

                // Ignore the status that appears the most
                for (t_status type = OPEN; type <= UNFILTERED; type++)
                    if (amount[type] > amount[default_status])
                        default_status = type;
                printf("Not shown: %d ports on state ", amount[default_status]);
                print_status_name(default_status);

                // Don't print anything if all the ports are on the same state
                if (amount[default_status] == g_scan.options.port_range.max - g_scan.options.port_range.min + 1)
                    continue;

                printf("PORT\tSTATE\n");
                // Print the ports that are not on the default state
                for (unsigned short index = g_scan.options.port_range.min;
                     index <= g_scan.options.port_range.max; index++)
                    if (ip->status[technique][index] != default_status) {
                        printf("%d\t", index);
                        print_status_name(ip->status[technique][index]);
                    }
            }
    }
}
