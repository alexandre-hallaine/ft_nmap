#include "functions.h"

#include <netdb.h>

unsigned short checksum(unsigned short *addr, size_t len)
{
    unsigned long sum = 0;

    // Add short by short the data of the packet
    for (; len >= sizeof(short); len -= sizeof(short))
        sum += *addr++;
    // If the length is odd, add the last byte
    if (len == sizeof(char))
        sum += *(unsigned char *)addr;

    // If the sum is bigger than 16bits, add the carry
    unsigned char bits = sizeof(short) * 8;
    while (sum >> bits)
        sum = (sum & ((1 << bits) - 1)) + (sum >> bits);

    // Reverse the bits
    return (~sum);
}

void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP)
{
    unsigned char ip_size = g_scan.options.family == AF_INET ? sizeof(t_ipv4_pseudo_header) : sizeof(t_ipv6_pseudo_header);
    char buffer[ip_size + packet_size];

    // Create the pseudo header of IPv4 or IPv6 and copy it to the start of the buffer
    if (g_scan.options.family == AF_INET)
    {
        t_ipv4_pseudo_header pseudo_header = 
        {
            .source_address = g_scan.interface.ipv4.sin_addr.s_addr,
            .destination_address = IP->addr.ipv4.sin_addr.s_addr,
            .protocol = protocol,
            .length = htons(packet_size)
        };

        ft_memcpy(buffer, &pseudo_header, ip_size);
    }
    else
    {
        t_ipv6_pseudo_header pseudo_header =
        {
            .length = htonl(packet_size),
            .next_header = protocol
        };

        // We need to copy the address byte by byte because it is an array
        ft_memcpy(pseudo_header.source_address, &g_scan.interface.ipv6.sin6_addr, sizeof(pseudo_header.source_address));
        ft_memcpy(pseudo_header.destination_address, &IP->addr.ipv6.sin6_addr, sizeof(pseudo_header.destination_address));

        ft_memcpy(buffer, &pseudo_header, ip_size);
    }

    // Copy the packet to the rest of the buffer
    ft_memcpy(buffer + ip_size, packet, packet_size);

    // Calculate the checksum for TCP or UDP
    if (protocol == IPPROTO_TCP)
        packet->tcp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
    else if (protocol == IPPROTO_UDP)
        packet->udp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
}
