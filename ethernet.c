// ############## LLM Generated Code Begins ##############
#include "ethernet.h"
#include <stdio.h>

int parse_ethernet(const unsigned char *packet, int len, uint16_t *ethertype) {
    if (len < 14) return -1;
    
    const unsigned char *dst_mac = packet;
    const unsigned char *src_mac = packet + 6;
    *ethertype = (packet[12] << 8) | packet[13];
    
    printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | Src MAC: %02X:%02X:%02X:%02X:%02X:%02X |\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    
    printf("EtherType: ");
    switch(*ethertype) {
        case ETHERTYPE_IP:
            printf("IPv4 (0x%04X)\n", *ethertype);
            break;
        case ETHERTYPE_IPV6:
            printf("IPv6 (0x%04X)\n", *ethertype);
            break;
        case ETHERTYPE_ARP:
            printf("ARP (0x%04X)\n", *ethertype);
            break;
        default:
            printf("Unknown (0x%04X)\n", *ethertype);
            break;
    }
    
    return 14;  // Ethernet header size
}

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
