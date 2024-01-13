#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// utils.c
void error(int code, char *fmt, ...);
char *get_technique_name(t_technique technique);
void print_status_name(t_status status);
void free_IPs();

// address.c
t_addr get_interface(int family);
t_addrinfo get_info(char *host);

// parser.c
void usage(char *program);
void parse_port_range(char *port_range);
void parse_technique(char *technique);
void command_parser(int argc, char *argv[]);

// packet.c
t_packet create_packet(t_technique technique);

// checksum.c
void calculate_checksum(u_int8_t protocol, t_packet *packet, unsigned short packet_size);

// send.c
void send_packet(t_technique technique);
void send_packet_solo(t_technique technique, unsigned short small, unsigned short big);

// result.c
void print_result();

// receive.c
void packet_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *data);

#endif