#include "types.h"

t_packet_header create_packet(t_technique technique)
{
    t_packet_header packet = {0};

    // For UDP, we only need to set the source port and the length
    if (technique == UDP)
    {
        packet.udp.source = htons(technique);
        packet.udp.len = htons(sizeof(struct udphdr));
        return packet;
    }

    // For TCP, we need to set the source port, the window size and the data offset
    packet.tcp.source = htons(technique);
    packet.tcp.doff = 5; // 5 * 4 bytes (32 bits) = 20 bytes (the size of the header)

    // And we need to set the flags
    packet.tcp.ack = technique == ACK;
    packet.tcp.syn = technique == SYN;
    packet.tcp.fin = technique == FIN || technique == XMAS;
    packet.tcp.psh = technique == XMAS;
    packet.tcp.urg = technique == XMAS;

    // Used for debugging purposes to see which technique is used
    // printf("\nack: %d, syn: %d, fin: %d, psh: %d, urg: %d\n", packet.tcp.ack, packet.tcp.syn, packet.tcp.fin, packet.tcp.psh, packet.tcp.urg);
    return packet;
}
