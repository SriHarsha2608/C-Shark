// ############## LLM Generated Code Begins ##############
#include "storage.h"
#include "inspector.h"
#include "ethernet.h"
#include "network.h"
#include "transport.h"
#include "application.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static stored_packet_t packets[MAX_PACKETS];
static int packet_count = 0;
static int storage_initialized = 0;

void storage_init(void) {
    if (!storage_initialized) {
        memset(packets, 0, sizeof(packets));
        packet_count = 0;
        storage_initialized = 1;
    }
}

void storage_clear(void) {
    for (int i = 0; i < packet_count; i++) {
        if (packets[i].data) {
            free(packets[i].data);
            packets[i].data = NULL;
        }
    }
    packet_count = 0;
}

int storage_add_packet(const uint8_t *data, uint32_t length, const struct timeval *ts) {
    if (packet_count >= MAX_PACKETS) {
        return 0;  // Storage full
    }
    
    // Allocate memory for packet data
    packets[packet_count].data = (uint8_t*)malloc(length);
    if (!packets[packet_count].data) {
        return 0;  // Allocation failed
    }
    
    // Copy packet data
    memcpy(packets[packet_count].data, data, length);
    packets[packet_count].length = length;
    packets[packet_count].timestamp = *ts;
    
    packet_count++;
    return 1;
}

int storage_get_count(void) {
    return packet_count;
}

const stored_packet_t* storage_get_packet(int index) {
    if (index < 0 || index >= packet_count) {
        return NULL;
    }
    return &packets[index];
}

void storage_inspect_session(void) {
    if (packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Run a capture session first.\n");
        return;
    }
    
    printf("\n[C-Shark] ========== LAST SESSION SUMMARY ==========\n");
    printf("[C-Shark] Total packets captured: %d\n", packet_count);
    printf("[C-Shark] Storage capacity: %d packets\n", MAX_PACKETS);
    printf("[C-Shark] ================================================\n\n");
    
    // Display summary list
    printf("%-6s %-20s %-8s %-30s %-30s %s\n", 
           "ID", "Timestamp", "Length", "Source", "Destination", "Protocol");
    printf("-----------------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < packet_count; i++) {
        const stored_packet_t *pkt = &packets[i];
        
        // Extract basic info for summary
        char src_info[40] = "N/A";
        char dst_info[40] = "N/A";
        char proto_info[10] = "Unknown";
        
        if (pkt->length >= 14) {
            uint16_t ethertype = (pkt->data[12] << 8) | pkt->data[13];
            
            if (ethertype == ETHERTYPE_IP && pkt->length >= 34) {
                // IPv4
                snprintf(src_info, sizeof(src_info), "%d.%d.%d.%d",
                        pkt->data[26], pkt->data[27], pkt->data[28], pkt->data[29]);
                snprintf(dst_info, sizeof(dst_info), "%d.%d.%d.%d",
                        pkt->data[30], pkt->data[31], pkt->data[32], pkt->data[33]);
                
                uint8_t protocol = pkt->data[23];
                if (protocol == 6) snprintf(proto_info, sizeof(proto_info), "TCP");
                else if (protocol == 17) snprintf(proto_info, sizeof(proto_info), "UDP");
                else if (protocol == 1) snprintf(proto_info, sizeof(proto_info), "ICMP");
                else snprintf(proto_info, sizeof(proto_info), "IP/%d", protocol);
            } else if (ethertype == ETHERTYPE_ARP && pkt->length >= 42) {
                // ARP packet - extract sender and target IPs
                const uint8_t *arp_hdr = pkt->data + 14;
                
                // Check if it's IPv4 ARP (hardware type=1, protocol type=0x0800)
                uint16_t hw_type = (arp_hdr[0] << 8) | arp_hdr[1];
                uint16_t proto_type = (arp_hdr[2] << 8) | arp_hdr[3];
                uint8_t hw_len = arp_hdr[4];
                uint8_t proto_len = arp_hdr[5];
                
                if (hw_type == 1 && proto_type == 0x0800 && hw_len == 6 && proto_len == 4) {
                    // Sender IP (bytes 14-17 of ARP packet)
                    snprintf(src_info, sizeof(src_info), "%d.%d.%d.%d",
                            arp_hdr[14], arp_hdr[15], arp_hdr[16], arp_hdr[17]);
                    
                    // Target IP (bytes 24-27 of ARP packet)
                    snprintf(dst_info, sizeof(dst_info), "%d.%d.%d.%d",
                            arp_hdr[24], arp_hdr[25], arp_hdr[26], arp_hdr[27]);
                } else {
                    snprintf(src_info, sizeof(src_info), "ARP");
                    snprintf(dst_info, sizeof(dst_info), "ARP");
                }
                
                snprintf(proto_info, sizeof(proto_info), "ARP");
            } else if (ethertype == ETHERTYPE_IPV6 && pkt->length >= 54) {
                // IPv6 - show abbreviated addresses (first 4 segments)
                const uint8_t *ipv6_hdr = pkt->data + 14;
                
                // Source IPv6 (bytes 8-23 of IPv6 header)
                snprintf(src_info, sizeof(src_info), "%02x%02x:%02x%02x:%02x%02x:%02x%02x...",
                        ipv6_hdr[8], ipv6_hdr[9], ipv6_hdr[10], ipv6_hdr[11],
                        ipv6_hdr[12], ipv6_hdr[13], ipv6_hdr[14], ipv6_hdr[15]);
                
                // Destination IPv6 (bytes 24-39 of IPv6 header)
                snprintf(dst_info, sizeof(dst_info), "%02x%02x:%02x%02x:%02x%02x:%02x%02x...",
                        ipv6_hdr[24], ipv6_hdr[25], ipv6_hdr[26], ipv6_hdr[27],
                        ipv6_hdr[28], ipv6_hdr[29], ipv6_hdr[30], ipv6_hdr[31]);
                
                // Next Header (byte 6 of IPv6 header)
                uint8_t next_header = ipv6_hdr[6];
                if (next_header == 6) snprintf(proto_info, sizeof(proto_info), "TCP");
                else if (next_header == 17) snprintf(proto_info, sizeof(proto_info), "UDP");
                else if (next_header == 58) snprintf(proto_info, sizeof(proto_info), "ICMPv6");
                else snprintf(proto_info, sizeof(proto_info), "IPv6/%d", next_header);
            }
        }
        
        printf("%-6d %ld.%06ld  %-8u %-30s %-30s %s\n",
               i + 1,
               (long)pkt->timestamp.tv_sec,
               (long)pkt->timestamp.tv_usec,
               pkt->length,
               src_info,
               dst_info,
               proto_info);
    }
    
    printf("\n[C-Shark] ================================================\n");
}

void storage_inspect_interactive(void) {
    if (packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Run a capture session first.\n");
        return;
    }
    
    // First show summary
    storage_inspect_session();
    
    // Then allow detailed inspection
    while (1) {
        char *input = read_input_line("\nEnter packet ID to inspect (or 0 to return): ");
        if (!input) {
            // Ctrl+D
            printf("\n");
            break;
        }
        
        int packet_id = atoi(input);
        free(input);
        
        if (packet_id == 0) {
            break;
        }
        
        if (packet_id < 1 || packet_id > packet_count) {
            printf("[C-Shark] Invalid packet ID. Please enter a number between 1 and %d.\n", packet_count);
            continue;
        }
        
        // Get the packet
        const stored_packet_t *pkt = &packets[packet_id - 1];
        
        // Display detailed inspection
        inspect_packet_detailed(pkt->data, pkt->length, 
                               pkt->timestamp.tv_sec, pkt->timestamp.tv_usec, 
                               packet_id);
        
        getchar();  // Wait for Enter
    }
}

void storage_cleanup(void) {
    storage_clear();
    storage_initialized = 0;
}


// ############## LLM Generated Code Ends ################
