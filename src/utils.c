#include "types.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void error(int code, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(code); // need to explain something to you on this
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
		return NULL; // to avoid warning
	}
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
