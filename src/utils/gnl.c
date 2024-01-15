#include "functions.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>

typedef	struct
{
    char let;
    void *next;
} t_gnl;

int get_next_line(int fd, char **line)
{
    t_gnl *list = ft_calloc(1, sizeof(t_gnl));
    if (!list)
        error(1, "get_next_line: ft_calloc failed\n");

    t_gnl *begin = list;
    int ret;
    int loop = 0;
    int size;

    for (size = 1; (ret = read(fd, &list->let, 1)) > 0 && list->let != '\n'; size++)
    {
        list->next = ft_calloc(1, sizeof(t_gnl));
        if (!list->next)
            error(1, "get_next_line: ft_calloc failed\n");
        list = list->next;
    }

    line[0] = ft_calloc(1, size);
    if (!line[0])
        error(1, "get_next_line: ft_calloc failed\n");

    list = begin;
    for (loop = 0; list; loop++, begin = list)
    {
        line[0][loop] = list->let;
        list = list->next;
        free(begin);
    }

	line[0][loop - 1] = 0;
    return (ret);
}