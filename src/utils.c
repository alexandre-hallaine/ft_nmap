#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void error(int code, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(code);
}
