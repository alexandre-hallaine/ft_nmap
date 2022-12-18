#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// address.c
uint32_t get_interface();
t_addrinfo get_info(char *host);

// checksum.c
unsigned short tcp_checksum_ack(t_packet packet);
unsigned short tcp_checksum_syn(t_packet packet);

// packet_syn.c
void create_packet_syn();
void send_packet_syn(unsigned short port);
void receive_packet_syn(unsigned short port);

// packet_ack.c
void create_packet_ack();
void send_packet_ack(unsigned short port);
void receive_packet_ack(unsigned short port);

// utils.c
void error(int code, char *fmt, ...);

#endif