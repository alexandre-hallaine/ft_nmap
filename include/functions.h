#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// address.c
t_addr get_interface(int family);
t_addrinfo get_info(char *host);

// parser.c
void command_parser(int argc, char *argv[]);

// packet.c
t_packet create_packet_ack();
t_packet create_packet_syn();
t_packet create_packet_fin();
t_packet create_packet_null();
t_packet create_packet_xmas();
t_packet create_packet_udp();

// checksum.c
void update_checksum(u_int8_t protocol_type, t_packet *packet, unsigned short packet_size);

// send.c
void send_packet(t_protocol protocol);

// tcp.c
// void create_packet_ack();
// void create_packet_syn();
// void create_packet_fin();
// void create_packet_null();
// void create_packet_xmas();
// void send_packet_tcp(int socket, unsigned short port);

// udp.c
// void send_packet_udp(int socket, unsigned short port);

// packet_ack.c
// void receive_packet_ack(unsigned short port);

// packet_syn.c
// void receive_packet_syn(unsigned short port);

// packet_others.c
// void receive_packet_others(unsigned short port);

// utils.c
void error(int code, char *fmt, ...);

#endif