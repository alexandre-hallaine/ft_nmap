#include "functions.h"

#include <stddef.h>
#include <unistd.h>

void flag_parser(unsigned short *index, char *argv[])
{
	// may need to be modified when more options are added
	if (argv[*index][2] != '\0') // use -h instead of -help
		error(2, "usage: %s: invalid option\n", argv[*index]);

	switch (argv[*index][1]) // repeated code perhaps we can figure out a way to make this more efficient (make shit fall into h ?)
	{
	case 'h':
		usage(argv[0]);
		break;

	case 'p':
		(*index)++;
		if (argv[*index] == NULL)
			usage(argv[0]);

		parse_port_range(argv[*index]);
		break;

	case 's':
		(*index)++;
		if (argv[*index] == NULL)
			usage(argv[0]);

		parse_technique(argv[*index]);
		// bool check here
		break;

	default:
		error(2, "usage: %s: invalid option\n", argv[*index]);
	}
}

// naming
void command_parser(int argc, char *argv[])
{
	if (getuid() != 0)
		error(1, "usage: You need to be root to run this program\n"); // move to main

	g_scan.options.port_min = 1;
	g_scan.options.port_max = 1024; // change with define

	unsigned short index = 1; // for loop is better ?
	while (index < argc && argv[index][0] == '-')
	{
		flag_parser(&index, argv);
		index++;
	}

	// if no technique is specified, scan with all of them
    // remove block
	{
		bool technique_specified = false; // can't this be checked within flag_parser ?
		for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
			if (g_scan.options.techniques[i])
				technique_specified = true; // why not just break here ?

		if (!technique_specified)
			for (unsigned char i = 0; i < TECHNIQUE_COUNT; i++)
				g_scan.options.techniques[i] = true;
            //  memset(g_scan.options.techniques, true, TECHNIQUE_COUNT); imo this is better
	}

    // I feel like this should be done before the flags
	if (index != argc - 1)
		usage(argv[0]);
	g_scan.destination = get_info(argv[index]);
	g_scan.interface = get_interface(g_scan.destination.family);
}
