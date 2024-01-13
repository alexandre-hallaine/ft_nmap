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
