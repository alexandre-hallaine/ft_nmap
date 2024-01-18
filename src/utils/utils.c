#include "functions.h"

#include <stdlib.h>
#include <stdarg.h>

void free_IPs()
{
    t_IP *head = g_scan.ip;
    t_IP *tmp = NULL;

    while (head)
    {
        tmp = head;
        head = head->next;
        free(tmp);
    }
}

void error(int code, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    free_IPs();
    exit(code);
}

void add_IP(t_IP addr) {
    t_IP *head = g_scan.ip;
    t_IP *new_node = NULL;

    for (; head; head = head->next)
    {
        if (g_scan.ip_count > MAX_IPS)
            error(2, "add_IP: too many IPs (max: %d)\n", MAX_IPS);
        if ((g_scan.options.family == AF_INET && ft_memcmp(&head->addr.ipv4.sin_addr, &addr.addr.ipv4.sin_addr, sizeof(struct in_addr)) == 0)
            || (g_scan.options.family == AF_INET6 && ft_memcmp(&head->addr.ipv6.sin6_addr, &addr.addr.ipv6.sin6_addr, sizeof(struct in6_addr)) == 0))
        {
            fprintf(stderr, "Warning: %s: duplicate IP, ignoring\n", addr.name);
            return;
        }
        if (!head->next)
            break;
    }

    new_node = ft_calloc(1, sizeof(t_IP));
    if (!new_node)
        error(1, "add_to_list: ft_calloc failed\n");
    ft_memcpy(new_node, &addr, sizeof(t_IP));

    new_node->next = NULL;

    if (!g_scan.ip)
        g_scan.ip = new_node;
    else {
        ft_strcat(g_scan.filter, " or ");
        head->next = new_node;
    }
    g_scan.ip_count++;

    char ip[INET6_ADDRSTRLEN] = {0};
    if (g_scan.options.family == AF_INET)
        inet_ntop(g_scan.options.family, &addr.addr.ipv4.sin_addr, ip, sizeof(ip));
    else if (g_scan.options.family == AF_INET6)
        inet_ntop(g_scan.options.family, &addr.addr.ipv6.sin6_addr, ip, sizeof(ip));

    ft_strcat(g_scan.filter, "src ");
    ft_strcat(g_scan.filter, ip);
}

char *get_technique_name(t_technique technique)
{
    switch (technique)
    {
    case ACK:
        return "ACK";
    case SYN:
        return "SYN";
    case FIN:
        return "FIN";
    case NUL:
        return "NUL";
    case XMAS:
        return "XMAS";
    case UDP:
        return "UDP";
    default:
        error(3, "get_technique_name: unknown technique\n");
    }
    return NULL;
}

void print_status_name(t_status status)
{
    if (status == UNSCANNED)
        printf("UNSCANNED ");
    if (status & OPEN)
        printf("OPEN ");
    if (status & CLOSED)
        printf("CLOSED ");
    if (status & FILTERED)
        printf("FILTERED ");
    if (status & UNFILTERED)
        printf("UNFILTERED ");
    printf("\n");
}

int is_number(char *str)
{
    for (unsigned char i = 0; i < ft_strlen(str); i++)
        if (str[i] < '0' || str[i] > '9')
            return 0;
    return 1;
}

void check_down()
{
    bool all_down = true;
    for (t_IP *IP = g_scan.ip; IP != NULL; IP = IP->next)
        if (!IP->is_down)
        {
            all_down = false;
            break;
        }

    if (all_down)
        error(1, "None of the hosts specified are up. Stopping now.\n");
}

int get_number(char *str)
{
    if (ft_strlen(str) == 0)
        error(2, "get_number: empty string\n");
    else if (!is_number(str))
        error(2, "get_number: %s: not a number\n", str);
    return ft_atoi(str);
}
