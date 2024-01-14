#include "types.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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

    if (!new_node) {
        error(1, "add_to_list: malloc failed\n");
    }

    new_node->destination = addr;
    new_node->next = NULL;

    if (!g_scan.IPs)
        g_scan.IPs = new_node;
    else
        head->next = new_node;
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
