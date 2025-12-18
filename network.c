// ############## LLM Generated Code Begins ##############
#include "network.h"
#include <stdio.h>
#include <arpa/inet.h>

void parse_arp(const unsigned char *packet, int len) {
    if (len < 28) return;
    
    uint16_t hw_type = (packet[0] << 8) | packet[1];
    uint16_t proto_type = (packet[2] << 8) | packet[3];
    uint8_t hw_len = packet[4];
    uint8_t proto_len = packet[5];
    uint16_t opcode = (packet[6] << 8) | packet[7];
    
    const unsigned char *sender_mac = packet + 8;
    const unsigned char *sender_ip = packet + 14;
    const unsigned char *target_mac = packet + 18;
    const unsigned char *target_ip = packet + 24;
    
    printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %d.%d.%d.%d | Target IP: %d.%d.%d.%d\n",
           opcode == 1 ? "Request" : (opcode == 2 ? "Reply" : "Unknown"),
           opcode,
           sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    
    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
           target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
    
    printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
           hw_type, proto_type, hw_len, proto_len);
}

int parse_ipv4(const unsigned char *packet, int len, uint8_t *protocol, const unsigned char **next_layer) {
    if (len < 20) return -1;
    
    uint8_t version_ihl = packet[0];
    uint8_t ihl = (version_ihl & 0x0F) * 4;
    uint8_t ttl = packet[8];
    *protocol = packet[9];
    uint16_t total_len = (packet[2] << 8) | packet[3];
    uint16_t id = (packet[4] << 8) | packet[5];
    uint16_t flags_frag = (packet[6] << 8) | packet[7];
    
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, packet + 12, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, packet + 16, dst_ip, INET_ADDRSTRLEN);
    
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: ", src_ip, dst_ip);
    
    switch(*protocol) {
        case IPPROTO_TCP:
            printf("TCP (%d) |\n", *protocol);
            break;
        case IPPROTO_UDP:
            printf("UDP (%d) |\n", *protocol);
            break;
        case IPPROTO_ICMP:
            printf("ICMP (%d) |\n", *protocol);
            break;
        default:
            printf("Unknown (%d) |\n", *protocol);
            break;
    }
    
    printf("TTL: %d\n", ttl);
    printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes", id, total_len, ihl);
    
    // Print flags if present
    uint8_t df = (flags_frag >> 14) & 0x01;
    uint8_t mf = (flags_frag >> 13) & 0x01;
    if (df || mf) {
        printf(" | Flags: [");
        if (df) printf("DF");
        if (df && mf) printf(",");
        if (mf) printf("MF");
        printf("]");
    }
    printf("\n");
    
    *next_layer = packet + ihl;
    return total_len - ihl;  // Payload length
}

int parse_ipv6(const unsigned char *packet, int len, uint8_t *next_header, const unsigned char **next_layer) {
    if (len < 40) return -1;
    
    uint32_t ver_tc_fl = (packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];
    uint8_t traffic_class = (ver_tc_fl >> 20) & 0xFF;
    uint32_t flow_label = ver_tc_fl & 0xFFFFF;
    uint16_t payload_len = (packet[4] << 8) | packet[5];
    *next_header = packet[6];
    uint8_t hop_limit = packet[7];
    
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, packet + 8, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, packet + 24, dst_ip, INET6_ADDRSTRLEN);
    
    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
    printf("Next Header: ");
    
    switch(*next_header) {
        case IPPROTO_TCP:
            printf("TCP (%d)", *next_header);
            break;
        case IPPROTO_UDP:
            printf("UDP (%d)", *next_header);
            break;
        case 58:  // ICMPv6
            printf("ICMPv6 (%d)", *next_header);
            break;
        default:
            printf("Unknown (%d)", *next_header);
            break;
    }
    
    printf(" | Hop Limit: %d\n", hop_limit);
    printf("Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           traffic_class, flow_label, payload_len);
    
    *next_layer = packet + 40;
    return payload_len;
}


// ############## LLM Generated Code Ends ################
