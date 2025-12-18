// ############## LLM Generated Code Begins ##############
#include "application.h"
#include <stdio.h>
#include <ctype.h>

// Helper: Print hex dump with ASCII
static void print_hex_dump(const unsigned char *data, int len) {
    int display_len = (len > 64) ? 64 : len;
    for (int i = 0; i < display_len; i += 16) {
        // Print hex
        for (int j = 0; j < 16 && (i + j) < display_len; j++) {
            printf("%02X ", data[i + j]);
        }
        // Padding for incomplete lines
        for (int j = display_len - i; j < 16; j++) {
            printf("   ");
        }
        printf(" ");
        // Print ASCII
        for (int j = 0; j < 16 && (i + j) < display_len; j++) {
            char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

void parse_payload(const unsigned char *payload, int len, uint16_t sport, uint16_t dport) {
    if (len <= 0) return;
    
    printf("L7 (Payload): Identified as ");
    
    // Identify based on port
    if (sport == 80 || dport == 80) {
        printf("HTTP on port 80");
    } else if (sport == 443 || dport == 443) {
        printf("HTTPS/TLS on port 443");
    } else if (sport == 53 || dport == 53) {
        printf("DNS on port 53");
    } else if (sport == 8080 || dport == 8080) {
        printf("HTTP-Alt on port 8080");
    } else {
        printf("Unknown");
    }
    
    printf(" - %d bytes\n", len);
    
    if (len > 0) {
        printf("Data (first %d bytes):\n", len > 64 ? 64 : len);
        print_hex_dump(payload, len);
    }
}

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
