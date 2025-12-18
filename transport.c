// ############## LLM Generated Code Begins ##############
#include "transport.h"
#include <stdio.h>

const char* get_port_name(uint16_t port) {
    switch(port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        case 21: return "FTP";
        case 22: return "SSH";
        case 25: return "SMTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        default: return NULL;
    }
}

int parse_tcp(const unsigned char *packet, int len, uint16_t *sport, uint16_t *dport) {
    if (len < 20) return -1;
    
    *sport = (packet[0] << 8) | packet[1];
    *dport = (packet[2] << 8) | packet[3];
    uint32_t seq = (packet[4] << 24) | (packet[5] << 16) | (packet[6] << 8) | packet[7];
    uint32_t ack = (packet[8] << 24) | (packet[9] << 16) | (packet[10] << 8) | packet[11];
    uint8_t data_offset = (packet[12] >> 4) * 4;
    uint8_t flags = packet[13];
    uint16_t window = (packet[14] << 8) | packet[15];
    uint16_t checksum = (packet[16] << 8) | packet[17];
    
    const char *sport_name = get_port_name(*sport);
    const char *dport_name = get_port_name(*dport);
    
    printf("L4 (TCP): Src Port: %d", *sport);
    if (sport_name) printf(" (%s)", sport_name);
    printf(" | Dst Port: %d", *dport);
    if (dport_name) printf(" (%s)", dport_name);
    printf(" | Seq: %u | Ack: %u\n", seq, ack);
    
    printf(" | Flags: [");
    int first = 1;
    if (flags & 0x02) { if (!first) printf(","); printf("SYN"); first = 0; }
    if (flags & 0x10) { if (!first) printf(","); printf("ACK"); first = 0; }
    if (flags & 0x01) { if (!first) printf(","); printf("FIN"); first = 0; }
    if (flags & 0x04) { if (!first) printf(","); printf("RST"); first = 0; }
    if (flags & 0x08) { if (!first) printf(","); printf("PSH"); first = 0; }
    if (flags & 0x20) { if (!first) printf(","); printf("URG"); first = 0; }
    printf("]\n");
    
    printf("Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
           window, checksum, data_offset);
    
    return data_offset;
}

int parse_udp(const unsigned char *packet, int len, uint16_t *sport, uint16_t *dport) {
    if (len < 8) return -1;
    
    *sport = (packet[0] << 8) | packet[1];
    *dport = (packet[2] << 8) | packet[3];
    uint16_t length = (packet[4] << 8) | packet[5];
    uint16_t checksum = (packet[6] << 8) | packet[7];
    
    const char *sport_name = get_port_name(*sport);
    const char *dport_name = get_port_name(*dport);
    
    printf("L4 (UDP): Src Port: %d", *sport);
    if (sport_name) printf(" (%s)", sport_name);
    printf(" | Dst Port: %d", *dport);
    if (dport_name) printf(" (%s)", dport_name);
    printf(" | Length: %d | Checksum: 0x%04X\n", length, checksum);
    
    return 8;  // UDP header size
}


// ############## LLM Generated Code Ends ################
