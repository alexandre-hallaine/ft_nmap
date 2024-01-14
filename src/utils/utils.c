#include "types.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void free_IPs()
{
    t_IP *head = g_scan.IPs;
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

void add_IP(t_addrinfo addr) {
    t_IP *head = g_scan.IPs;
    t_IP *new_node = NULL;

    for (; head && head->next; head = head->next);
    new_node = malloc(sizeof(t_IP));

    if (!new_node)
        error(1, "add_to_list: malloc failed\n");

    new_node->destination = addr;
    new_node->next = NULL;

    if (!g_scan.IPs)
        g_scan.IPs = new_node;
    else {
        strcat(g_scan.filter, " or ");
        head->next = new_node;
    }

    char ip[INET6_ADDRSTRLEN] = {0};
    if (g_scan.family == AF_INET)
        inet_ntop(g_scan.family, &addr.addr.in.sin_addr, ip, sizeof(ip));
    else if (g_scan.family == AF_INET6)
        inet_ntop(g_scan.family, &addr.addr.in6.sin6_addr, ip, sizeof(ip));
    strcat(g_scan.filter, "src ");
    strcat(g_scan.filter, ip);
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

int _ceil(float num) {
    if (num < 0)
        return (int)num;
    return (int)num + 1;
}

char *ft_memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}

char *ft_strchr(const char *s, int c)
{
    while (*s)
    {
        if (*s == c)
            return (char *)s;
        s++;
    }
    if (*s == c)
        return (char *)s;
    return NULL;
}

char *ft_bzero(void *str, size_t n)
{
    char *s = str;
    while (n--)
        *s++ = 0;
    return str;
}

int is_number(char *str)
{
    for (unsigned char i = 0; i < strlen(str); i++)
        if (str[i] < '0' || str[i] > '9')
            return 0;
    return 1;
}
