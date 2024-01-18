#include "functions.h"

void flag_parser(unsigned short *index, char *argv[])
{
    for (char *flag = argv[*index] + 1; *flag != '\0'; flag++) {
        if (ft_strchr("pst", *flag)) {
            if (flag[1] != '\0')
                error(2, "parser: you can't combine flags after one needs an argument\n");
            if (argv[(*index)++] == NULL)
                usage(argv[0]);
        }

        switch (*flag) {

            case 'p':
                parse_port_range(argv[*index]);
                break;

            case 's':
                parse_technique(argv[*index]);
                break;

            case 't':
                parse_thread(argv[*index]);
                break;

            case 'f':
                g_scan.options.file = true;
                break;

            case 'h':
                usage(argv[0]);
                break;

            case '6':
                g_scan.options.family = AF_INET6;
                break;

            case 'u':
                g_scan.options.ping = true;
                break;

            case 'r':
                g_scan.options.traceroute = true;
                break;

            case 'v':
                g_scan.options.verbose = 1;
                break;

            case 'V':
                g_scan.options.verbose = 2;
                break;

            case 'm':
                g_scan.options.timestamp = true;
                break;

            default:
                error(2, "usage: %s: invalid option\n", argv[*index]);
                return;
        }
    }
}
