// ############## LLM Generated Code Begins ##############
#ifndef INSPECTOR_H
#define INSPECTOR_H

#include <stdint.h>

// Inspect a single packet in detail with hex dump and comprehensive analysis
void inspect_packet_detailed(const uint8_t *data, uint32_t length, 
                             long sec, long usec, int packet_id);

// Print full hex dump of packet
void print_full_hex_dump(const uint8_t *data, uint32_t length);

#endif

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
