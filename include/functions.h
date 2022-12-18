#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// address.c
uint32_t get_interface();
struct addrinfo get_info(char *host);

// checksum.c
unsigned short tcp_checksum(t_packet packet);

// packet.c
void create_packet();
void send_packet(unsigned short port);
void receive_packet(unsigned short port);

// utils.c
void error(int code, char *fmt, ...);

#endif