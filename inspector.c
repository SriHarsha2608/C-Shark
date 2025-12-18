// ############## LLM Generated Code Begins ##############
#include "inspector.h"
#include "ethernet.h"
#include "network.h"
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

void print_full_hex_dump(const uint8_t *data, uint32_t length) {
    printf("\n■ COMPLETE FRAME HEX DUMP\n\n");
    printf("    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F     ASCII\n");
    printf("----------------------------------------------------------------\n");
    
    for (uint32_t i = 0; i < length; i += 16) {
        printf("%04X  ", i);
        
        // Print hex bytes
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf("  ");
        
        // Print ASCII
        for (int j = 0; j < 16 && (i + j) < length; j++) {
            char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("\n");
    }
    printf("\n");
}

static void inspect_ethernet(const uint8_t *data, uint32_t length) {
    if (length < 14) return;
    
    printf("\n🔷 ETHERNET II FRAME (Layer 2)\n\n");
    
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           data[0], data[1], data[2], data[3], data[4], data[5]);
    
    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
           data[6], data[7], data[8], data[9], data[10], data[11]);
    
    uint16_t ethertype = (data[12] << 8) | data[13];
    printf("EtherType:       0x%04X ", ethertype);
    switch(ethertype) {
        case ETHERTYPE_IP:   printf("(IPv4)"); break;
        case ETHERTYPE_IPV6: printf("(IPv6)"); break;
        case ETHERTYPE_ARP:  printf("(ARP)"); break;
        default:             printf("(Unknown)"); break;
    }
    printf("\n");
}

static void inspect_ipv4(const uint8_t *data, uint32_t length) {
    if (length < 20) return;
    
    printf("\n🔷 IPv4 HEADER (Layer 3)\n\n");
    
    uint8_t version = (data[0] >> 4) & 0x0F;
    uint8_t ihl = data[0] & 0x0F;
    uint8_t header_len = ihl * 4;
    
    printf("Version:         %d\n", version);
    printf("Header Length:   %d bytes\n", header_len);
    
    uint16_t total_len = (data[2] << 8) | data[3];
    printf("Total Length:    %d bytes\n", total_len);
    
    uint16_t id = (data[4] << 8) | data[5];
    printf("Identification:  0x%04X\n", id);
    
    uint16_t flags_frag = (data[6] << 8) | data[7];
    uint8_t flags = (flags_frag >> 13) & 0x07;
    uint16_t frag_offset = flags_frag & 0x1FFF;
    printf("Flags:           ");
    if ((flags >> 1) & 1) printf("[DF] ");
    if (flags & 1) printf("[MF] ");
    if (!((flags >> 1) & 1) && !(flags & 1)) printf("[None]");
    printf("\n");
    if (frag_offset > 0) {
        printf("Fragment Offset: %d\n", frag_offset * 8);
    }
    
    uint8_t ttl = data[8];
    printf("TTL:             %d\n", ttl);
    
    uint8_t protocol = data[9];
    printf("Protocol:        ");
    switch(protocol) {
        case 1:  printf("ICMP (1)"); break;
        case 6:  printf("TCP (6)"); break;
        case 17: printf("UDP (17)"); break;
        default: printf("%d", protocol); break;
    }
    printf("\n");
    
    uint16_t checksum = (data[10] << 8) | data[11];
    printf("Header Checksum: 0x%04X\n", checksum);
    
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data + 12, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, data + 16, dst_ip, INET_ADDRSTRLEN);
    
    printf("Source IP:       %s\n", src_ip);
    printf("Destination IP:  %s\n", dst_ip);
}

static void inspect_tcp(const uint8_t *data, uint32_t length) {
    if (length < 20) return;
    
    printf("\n🔷 TCP HEADER (Layer 4)\n\n");
    
    uint16_t sport = (data[0] << 8) | data[1];
    printf("Source Port:     %d", sport);
    if (sport == 80) printf(" (HTTP)");
    else if (sport == 443) printf(" (HTTPS)");
    else if (sport == 53) printf(" (DNS)");
    else if (sport == 8080) printf(" (HTTP-Alt)");
    printf("\n");
    
    uint16_t dport = (data[2] << 8) | data[3];
    printf("Destination Port: %d", dport);
    if (dport == 80) printf(" (HTTP)");
    else if (dport == 443) printf(" (HTTPS)");
    else if (dport == 53) printf(" (DNS)");
    else if (dport == 8080) printf(" (HTTP-Alt)");
    printf("\n");
    
    uint32_t seq = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    printf("Sequence Number: %u\n", seq);
    
    uint32_t ack = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    printf("Acknowledgment:  %u\n", ack);
    
    uint8_t data_offset = (data[12] >> 4) * 4;
    printf("Header Length:   %d bytes\n", data_offset);
    
    uint8_t flags = data[13];
    printf("Flags:           [");
    int first = 1;
    if ((flags >> 5) & 1) { printf("URG"); first = 0; }
    if ((flags >> 4) & 1) { if (!first) printf(","); printf("ACK"); first = 0; }
    if ((flags >> 3) & 1) { if (!first) printf(","); printf("PSH"); first = 0; }
    if ((flags >> 2) & 1) { if (!first) printf(","); printf("RST"); first = 0; }
    if ((flags >> 1) & 1) { if (!first) printf(","); printf("SYN"); first = 0; }
    if (flags & 1) { if (!first) printf(","); printf("FIN"); first = 0; }
    printf("]\n");
    
    uint16_t window = (data[14] << 8) | data[15];
    printf("Window Size:     %d\n", window);
    
    uint16_t checksum = (data[16] << 8) | data[17];
    printf("Checksum:        0x%04X\n", checksum);
    
    if (data_offset > 20 && data_offset <= (int)length) {
        printf("TCP Options:     %d bytes\n", data_offset - 20);
    }
}

static void inspect_udp(const uint8_t *data, uint32_t length) {
    if (length < 8) return;
    
    printf("\n🔷 UDP HEADER (Layer 4)\n\n");
    
    uint16_t sport = (data[0] << 8) | data[1];
    printf("Source Port:     %d", sport);
    if (sport == 53) printf(" (DNS)");
    else if (sport == 67) printf(" (DHCP Server)");
    else if (sport == 68) printf(" (DHCP Client)");
    printf("\n");
    
    uint16_t dport = (data[2] << 8) | data[3];
    printf("Destination Port: %d", dport);
    if (dport == 53) printf(" (DNS)");
    else if (dport == 67) printf(" (DHCP Server)");
    else if (dport == 68) printf(" (DHCP Client)");
    printf("\n");
    
    uint16_t len = (data[4] << 8) | data[5];
    printf("Length:          %d bytes\n", len);
    
    uint16_t checksum = (data[6] << 8) | data[7];
    printf("Checksum:        0x%04X\n", checksum);
}

static void inspect_ipv6(const uint8_t *data, uint32_t length) {
    if (length < 40) return;
    
    printf("\n🔷 IPv6 HEADER (Layer 3)\n\n");
    
    uint8_t version = (data[0] >> 4) & 0x0F;
    printf("Version:         %d\n", version);
    
    uint8_t traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    printf("Traffic Class:   0x%02X\n", traffic_class);
    
    uint32_t flow_label = ((data[1] & 0x0F) << 16) | (data[2] << 8) | data[3];
    printf("Flow Label:      0x%05X\n", flow_label);
    
    uint16_t payload_len = (data[4] << 8) | data[5];
    printf("Payload Length:  %d bytes\n", payload_len);
    
    uint8_t next_header = data[6];
    printf("Next Header:     ");
    switch(next_header) {
        case 6:  printf("TCP (6)"); break;
        case 17: printf("UDP (17)"); break;
        case 58: printf("ICMPv6 (58)"); break;
        default: printf("%d", next_header); break;
    }
    printf("\n");
    
    uint8_t hop_limit = data[7];
    printf("Hop Limit:       %d\n", hop_limit);
    
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data + 8, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, data + 24, dst_ip, INET6_ADDRSTRLEN);
    
    printf("Source IP:       %s\n", src_ip);
    printf("Destination IP:  %s\n", dst_ip);
}

static void inspect_arp(const uint8_t *data, uint32_t length) {
    if (length < 28) return;
    
    printf("\n🔷 ARP PACKET (Layer 3)\n\n");
    
    uint16_t hw_type = (data[0] << 8) | data[1];
    printf("Hardware Type:   %d ", hw_type);
    if (hw_type == 1) printf("(Ethernet)");
    printf("\n");
    
    uint16_t proto_type = (data[2] << 8) | data[3];
    printf("Protocol Type:   0x%04X ", proto_type);
    if (proto_type == 0x0800) printf("(IPv4)");
    printf("\n");
    
    uint8_t hw_len = data[4];
    uint8_t proto_len = data[5];
    printf("Hardware Length: %d\n", hw_len);
    printf("Protocol Length: %d\n", proto_len);
    
    uint16_t operation = (data[6] << 8) | data[7];
    printf("Operation:       ");
    switch(operation) {
        case 1: printf("Request (1)"); break;
        case 2: printf("Reply (2)"); break;
        default: printf("%d", operation); break;
    }
    printf("\n");
    
    if (hw_len == 6 && proto_len == 4) {
        printf("Sender MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
               data[8], data[9], data[10], data[11], data[12], data[13]);
        
        printf("Sender IP:       %d.%d.%d.%d\n",
               data[14], data[15], data[16], data[17]);
        
        printf("Target MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
               data[18], data[19], data[20], data[21], data[22], data[23]);
        
        printf("Target IP:       %d.%d.%d.%d\n",
               data[24], data[25], data[26], data[27]);
    }
}

static void inspect_payload(const uint8_t *data, uint32_t length, uint16_t sport, uint16_t dport) {
    if (length == 0) return;
    
    printf("\n■ APPLICATION DATA (Layer 7)\n\n");
    printf("Payload Length:  %d bytes\n", length);
    printf("Protocol:        ");
    
    if (sport == 80 || dport == 80) {
        printf("HTTP\n");
    } else if (sport == 443 || dport == 443) {
        printf("HTTPS/TLS\n");
    } else if (sport == 53 || dport == 53) {
        printf("DNS\n");
    } else if (sport == 8080 || dport == 8080) {
        printf("HTTP-Alt\n");
    } else {
        printf("Unknown/Custom\n");
    }
    
    int display_len = length > 64 ? 64 : length;
    printf("\nFirst %d bytes of payload:\n\n", display_len);
    printf("    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F     ASCII\n");
    printf("----------------------------------------------------------------\n");
    
    for (int i = 0; i < display_len; i += 16) {
        printf("%04X  ", i);
        
        for (int j = 0; j < 16; j++) {
            if (i + j < display_len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf("  ");
        
        for (int j = 0; j < 16 && (i + j) < display_len; j++) {
            char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("\n");
    }
    
    if (length > 64) {
        printf("\n... and %d more bytes\n", length - 64);
    }
}

void inspect_packet_detailed(const uint8_t *data, uint32_t length, 
                             long sec, long usec, int packet_id) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("            C-SHARK DETAILED PACKET ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    printf("\n■ PACKET SUMMARY\n\n");
    printf("Packet ID:       #%d\n", packet_id);
    printf("Timestamp:       %ld.%06ld\n", sec, usec);
    printf("Frame Length:    %d bytes\n", length);
    printf("Captured:        %d bytes\n", length);
    
    // Full hex dump
    print_full_hex_dump(data, length);
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("            LAYER-BY-LAYER ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    // Ethernet
    inspect_ethernet(data, length);
    
    if (length < 14) return;
    
    uint16_t ethertype = (data[12] << 8) | data[13];
    const uint8_t *l3_data = data + 14;
    uint32_t l3_len = length - 14;
    
    if (ethertype == ETHERTYPE_ARP) {
        inspect_arp(l3_data, l3_len);
    } else if (ethertype == ETHERTYPE_IP && l3_len >= 20) {
        inspect_ipv4(l3_data, l3_len);
        
        uint8_t ihl = (l3_data[0] & 0x0F) * 4;
        uint8_t protocol = l3_data[9];
        const uint8_t *l4_data = l3_data + ihl;
        uint32_t l4_len = l3_len - ihl;
        
        if (protocol == 6 && l4_len >= 20) {  // TCP
            inspect_tcp(l4_data, l4_len);
            
            uint8_t tcp_hdr_len = (l4_data[12] >> 4) * 4;
            const uint8_t *payload = l4_data + tcp_hdr_len;
            uint32_t payload_len = l4_len - tcp_hdr_len;
            
            uint16_t sport = (l4_data[0] << 8) | l4_data[1];
            uint16_t dport = (l4_data[2] << 8) | l4_data[3];
            
            if (payload_len > 0) {
                inspect_payload(payload, payload_len, sport, dport);
            }
        } else if (protocol == 17 && l4_len >= 8) {  // UDP
            inspect_udp(l4_data, l4_len);
            
            const uint8_t *payload = l4_data + 8;
            uint32_t payload_len = l4_len - 8;
            
            uint16_t sport = (l4_data[0] << 8) | l4_data[1];
            uint16_t dport = (l4_data[2] << 8) | l4_data[3];
            
            if (payload_len > 0) {
                inspect_payload(payload, payload_len, sport, dport);
            }
        }
    } else if (ethertype == ETHERTYPE_IPV6 && l3_len >= 40) {
        inspect_ipv6(l3_data, l3_len);
        
        uint8_t next_header = l3_data[6];
        const uint8_t *l4_data = l3_data + 40;
        uint32_t l4_len = l3_len - 40;
        
        if (next_header == 6 && l4_len >= 20) {  // TCP
            inspect_tcp(l4_data, l4_len);
            
            uint8_t tcp_hdr_len = (l4_data[12] >> 4) * 4;
            const uint8_t *payload = l4_data + tcp_hdr_len;
            uint32_t payload_len = l4_len - tcp_hdr_len;
            
            uint16_t sport = (l4_data[0] << 8) | l4_data[1];
            uint16_t dport = (l4_data[2] << 8) | l4_data[3];
            
            if (payload_len > 0) {
                inspect_payload(payload, payload_len, sport, dport);
            }
        } else if (next_header == 17 && l4_len >= 8) {  // UDP
            inspect_udp(l4_data, l4_len);
            
            const uint8_t *payload = l4_data + 8;
            uint32_t payload_len = l4_len - 8;
            
            uint16_t sport = (l4_data[0] << 8) | l4_data[1];
            uint16_t dport = (l4_data[2] << 8) | l4_data[3];
            
            if (payload_len > 0) {
                inspect_payload(payload, payload_len, sport, dport);
            }
        }
    }
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    END OF PACKET ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\nPress Enter to continue...");
}

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
