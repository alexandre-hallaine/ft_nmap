#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// address.c
t_addr get_interface(sa_family_t family);
t_addrinfo get_info(char *host);

// checksum.c
unsigned short tcp_checksum(t_packet packet, unsigned short value);

// tcp.c
void send_packet_tcp(unsigned short port);

// packet_ack.c
void create_packet_ack();
void receive_packet_ack(unsigned short port);

// packet_syn.c
void create_packet_syn();
void receive_packet_syn(unsigned short port);

// packet_others.c
void create_packet_fin();
void create_packet_null();
void create_packet_xmas();
void receive_packet_others(unsigned short port);

// utils.c
void error(int code, char *fmt, ...);

#endif