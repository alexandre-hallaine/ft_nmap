#ifndef FONCTIONS_H
#define FONCTIONS_H

#include "types.h"

// utils.c
void error(int code, char *fmt, ...);
char *get_technique_name(t_technique technique);
void print_status_name(t_status status);
void add_IP(t_IP addr);
void free_IPs();
int is_number(char *str);

// libft.c
char *ft_bzero(void *str, size_t n);
void *ft_calloc(size_t count, size_t size);
int ft_ceil(float num);
char *ft_memcpy(void *dest, const void *src, size_t n);
char *ft_strchr(const char *s, int c);
void ft_usleep(long usec);
int ft_strlen(const char *s);
char ft_strcat(char *dest, const char *src);
int ft_memcmp(const void *s1, const void *s2, size_t n);
void *ft_memset(void *s, int c, size_t n);
int ft_strcmp(const char *s1, const char *s2);
int ft_atoi(const char *str);

// gnl.c
int get_next_line(int fd, char **line);

// address.c
t_sockaddr get_interface();
t_IP get_ip(char *host);

// parser.c
void init(int argc, char *argv[]);

// packet.c
t_packet_header create_packet(t_technique technique);

// checksum.c
unsigned short checksum(unsigned short *addr, size_t len);
void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP);

// send.c
void *routine(void *arg);
void thread_send();

// result.c
void print_result();

// receive.c
void packet_handler(unsigned char *, const struct pcap_pkthdr *, const unsigned char *data);

#endif