#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// utils.c
void error(int code, char *fmt, ...);
char *get_technique_name(t_technique technique);
void print_status_name(t_status status);
void add_IP(t_addrinfo addr);
void free_IPs();
int _ceil(float num);
char *ft_memcpy(void *dest, const void *src, size_t n);
char *ft_strchr(const char *s, int c);
char *ft_bzero(void *str, size_t n);
int is_number(char *str);

// gnl.c
int get_next_line(int fd, char **line);

// address.c
t_addr get_interface(int family);
t_addrinfo get_info(char *host);

// parser.c
void init(int argc, char *argv[]);

// packet.c
t_packet create_packet(t_technique technique);

// checksum.c
void calculate_checksum(u_int8_t protocol, t_packet *packet, unsigned short packet_size, t_IP *IP);

// send.c
void *routine(void *arg);
void thread_send();

// result.c
void print_result();

// receive.c
void packet_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *data);

#endif