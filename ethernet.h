// ############## LLM Generated Code Begins ##############
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_IPV6  0x86DD
#define ETHERTYPE_ARP   0x0806

// Parse Ethernet header and return header length
// ethertype will be filled with the EtherType value
int parse_ethernet(const unsigned char *packet, int len, uint16_t *ethertype);

#endif

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
