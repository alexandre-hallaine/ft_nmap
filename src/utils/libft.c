#include "types.h"

#include <stdlib.h>

char *ft_bzero(void *str, size_t n)
{
    char *s = str;
    while (n--)
        *s++ = 0;
    return str;
}

void *ft_calloc(size_t count, size_t size)
{
    void *ptr = malloc(count * size);
    if (!ptr)
        return NULL;
    ft_bzero(ptr, count * size);
    return ptr;
}

int ft_ceil(float num) {
    if (num < 0)
        return (int)num;
    return (int)num + 1;
}

char *ft_memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}

char *ft_strchr(const char *s, int c)
{
    while (*s)
    {
        if (*s == c)
            return (char *)s;
        s++;
    }
    if (*s == c)
        return (char *)s;
    return NULL;
}

void ft_usleep(long usec) {
    struct timeval start, current;

    gettimeofday(&start, NULL);
    long end = start.tv_usec + usec;

    do {
        gettimeofday(&current, NULL);
        if (current.tv_usec < start.tv_usec) {
            current.tv_usec += 1000000;
            current.tv_sec -= 1;
        }
    } while (current.tv_sec < start.tv_sec || (current.tv_sec == start.tv_sec && current.tv_usec < end));
}

int ft_strlen(const char *s)
{
    int i = 0;
    while (s[i])
        i++;
    return i;
}

char ft_strcat(char *dest, const char *src)
{
    int i = 0;
    int j = 0;
    while (dest[i])
        i++;
    while (src[j]) {
        dest[i] = src[j];
        i++;
        j++;
    }
    dest[i] = '\0';
    return *dest;
}

int ft_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;
    while (n--)
    {
        if (*p1 != *p2)
            return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

void *ft_memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}

int ft_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2)
    {
        if (*s1 != *s2)
            return *s1 - *s2;
        s1++;
        s2++;
    }
    if (*s1 != *s2)
        return *s1 - *s2;
    return 0;
}

int ft_atoi(const char *str)
{
    int i = 0;
    int sign = 1;
    int result = 0;

    while (str[i] == ' ' || str[i] == '\t' || str[i] == '\n' ||
           str[i] == '\v' || str[i] == '\f' || str[i] == '\r')
        i++;

    if (str[i] == '-')
        sign = -1;

    if (str[i] == '-' || str[i] == '+')
        i++;

    while (str[i] >= '0' && str[i] <= '9')
    {
        result = result * 10 + str[i] - '0';
        i++;
    }

    return result * sign;
}
