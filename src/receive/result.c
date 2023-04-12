#include "functions.h"

#include <stdio.h>

void print_result()
{
	unsigned short amount[(OPEN | CLOSED | FILTERED | UNFILTERED) + 1] = {0};
	for (unsigned short index = g_scan.options.port_min; index <= g_scan.options.port_max; index++)
		if (g_scan.status[index] != UNSCANNED)
			amount[g_scan.status[index]]++;

	t_status default_status = 0;
	for (t_status type = 1; type <= (OPEN | CLOSED | FILTERED | UNFILTERED); type++)
		if (amount[type] > amount[default_status])
			default_status = type;
	printf("Not shown: %d ports on state ", amount[default_status]);
	print_status_name(default_status);

	if (amount[default_status] == g_scan.options.port_max - g_scan.options.port_min + 1)
		return;

	printf("PORT\tSTATE\n");
	for (unsigned short index = g_scan.options.port_min; index <= g_scan.options.port_max; index++)
		if (g_scan.status[index] != UNSCANNED && g_scan.status[index] != default_status)
		{
			printf("%d\t", index);
			print_status_name(g_scan.status[index]);
		}
}
