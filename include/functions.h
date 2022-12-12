#ifndef FONCTIONS_H
#define FONCTIONS_H

// utils.c
void error(int code, char *fmt, ...);
unsigned short checksum(unsigned short *addr, size_t len);
int ft_strcmp(char *s1, char *s2);

// network.c
struct sockaddr_in *get_ifaddr();
struct addrinfo *get_addr(char *host);
void create_socket();

#endif