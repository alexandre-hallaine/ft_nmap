#include "functions.h"

void init_send()
{
    printf("Sending packets...\n");
    if (g_scan.options.thread_count > 1)
        thread_send();
    else {
        for (t_technique technique = 0; technique < TECHNIQUE_COUNT; technique++)
            if (g_scan.options.technique[technique])
            {
                if (g_scan.options.verbose)
                {
                    printf("%s... ", get_technique_name(technique));
                    fflush(stdout);
                }

                t_options *options = ft_calloc(1, sizeof(t_options));
                if (!options)
                    error(1, "main: ft_calloc failed\n");
                ft_memcpy(options, &g_scan.options, sizeof(t_options));
                for (t_technique i = 0; i < TECHNIQUE_COUNT; i++)
                    options->technique[i] = false;
                options->technique[technique] = true;
                routine(options);
            }
        if (g_scan.options.verbose)
            printf("\n");
    }
}
