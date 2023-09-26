#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// utils.c
void error(int code, char *fmt, ...);
char *get_technique_name(t_technique technique);
void print_status_name(t_status status);

// address.c
t_addr get_interface(int family);
t_addrinfo get_info(char *host);

// flags.c
void usage(char *program);
void parse_port_range(char *port_range);
void parse_technique(char *technique);

// parser.c
void command_parser(int argc, char *argv[]);

// packet.c
t_packet create_packet(t_technique technique);

// checksum.c
void update_checksum(u_int8_t protocol, t_packet *packet, unsigned short packet_size);

// send.c
void send_packet(t_technique technique);

// result.c
void print_result(t_technique technique);

// receive.c
void receive_packet(t_technique technique);

#endif