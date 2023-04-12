#include "functions.h"

t_scan g_scan = {0};

int main(int argc, char *argv[])
{
	command_parser(argc, argv);

	for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
		if (g_scan.options.techniques[i])
		{
			send_packet(i);
			receive_packet(i);
		}
}
