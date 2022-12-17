#ifndef FONCTIONS_H
#define FONCTIONS_H

// utils.c
void error(int code, char *fmt, ...);
unsigned short checksum(unsigned short *addr, size_t len);
int ft_strcmp(char *s1, char *s2);

// network.c
struct addrinfo get_addr(char *host);
uint32_t get_own_addr();
void create_socket();

#endif