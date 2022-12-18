#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// utils.c
void error(int code, char *fmt, ...);
unsigned short checksum(unsigned short *addr, size_t len);
int ft_strcmp(char *s1, char *s2);

// network.c
uint32_t get_interface_addr();
struct addrinfo get_addr(char *host);
void create_socket();
unsigned short tcp_checksum(struct data data);

#endif