// ############## LLM Generated Code Begins ##############
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <netinet/in.h>  // For IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP

// Parse ARP packet
void parse_arp(const unsigned char *packet, int len);

// Parse IPv4 header
// Returns payload length, fills protocol and next_layer pointer
int parse_ipv4(const unsigned char *packet, int len, uint8_t *protocol, const unsigned char **next_layer);

// Parse IPv6 header
// Returns payload length, fills next_header and next_layer pointer
int parse_ipv6(const unsigned char *packet, int len, uint8_t *next_header, const unsigned char **next_layer);

#endif


// ############## LLM Generated Code Ends ################
