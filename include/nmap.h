#ifndef NMAP_H
#define NMAP_H

#define OPT_SIZE 20

struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

void error(int code, char *fmt, ...);
unsigned short checksum(unsigned short *addr, size_t len);
int ft_strcmp(char *s1, char *s2);
#endif
