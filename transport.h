// ############## LLM Generated Code Begins ##############
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>

// Get protocol name from port number
const char* get_port_name(uint16_t port);

// Parse TCP header
// Returns TCP header length, fills sport and dport
int parse_tcp(const unsigned char *packet, int len, uint16_t *sport, uint16_t *dport);

// Parse UDP header
// Returns UDP header length (8), fills sport and dport
int parse_udp(const unsigned char *packet, int len, uint16_t *sport, uint16_t *dport);

#endif


// ############## LLM Generated Code Ends ################