// ############## LLM Generated Code Begins ##############
#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <sys/time.h>  // For struct timeval

#define MAX_PACKETS 10000

// Stored packet structure
typedef struct {
    uint8_t *data;           // Raw packet data
    uint32_t length;         // Packet length
    struct timeval timestamp; // Capture timestamp
} stored_packet_t;

// Initialize storage system
void storage_init(void);

// Clear all stored packets (frees memory)
void storage_clear(void);

// Add a packet to storage
// Returns 1 on success, 0 if storage is full
int storage_add_packet(const uint8_t *data, uint32_t length, const struct timeval *ts);

// Get number of packets currently stored
int storage_get_count(void);

// Get a specific packet by index (0-based)
// Returns NULL if index is out of range
const stored_packet_t* storage_get_packet(int index);

// Display summary of all stored packets
void storage_inspect_session(void);

// Interactive inspection - select specific packet for detailed analysis
void storage_inspect_interactive(void);

// Cleanup storage (call at program exit)
void storage_cleanup(void);

#endif


// ############## LLM Generated Code Ends ################
