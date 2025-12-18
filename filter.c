// ############## LLM Generated Code Begins ##############
#include "filter.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_filter_menu(void) {
    printf("\n[C-Shark] Select a protocol filter:\n\n");
    printf("1. HTTP (TCP port 80)\n");
    printf("2. HTTPS (TCP port 443)\n");
    printf("3. DNS (UDP/TCP port 53)\n");
    printf("4. ARP (Address Resolution Protocol)\n");
    printf("5. TCP (Transmission Control Protocol)\n");
    printf("6. UDP (User Datagram Protocol)\n");
    printf("7. Cancel (Return to Main Menu)\n");
}

char* get_filter_from_user(void) {
    char *filter_str = NULL;
    
    while (1) {
        display_filter_menu();
        
        char *choice = read_input_line("\nSelect filter (1-7): ");
        if (!choice) {
            // Ctrl+D detected
            return NULL;
        }
        
        int selection = atoi(choice);
        free(choice);
        
        switch (selection) {
            case 1:
                // HTTP: TCP port 80
                filter_str = strdup("tcp port 80");
                printf("\n[C-Shark] Filter applied: HTTP traffic (tcp port 80)\n");
                return filter_str;
                
            case 2:
                // HTTPS: TCP port 443
                filter_str = strdup("tcp port 443");
                printf("\n[C-Shark] Filter applied: HTTPS traffic (tcp port 443)\n");
                return filter_str;
                
            case 3:
                // DNS: UDP or TCP port 53
                filter_str = strdup("port 53");
                printf("\n[C-Shark] Filter applied: DNS traffic (port 53)\n");
                return filter_str;
                
            case 4:
                // ARP
                filter_str = strdup("arp");
                printf("\n[C-Shark] Filter applied: ARP traffic\n");
                return filter_str;
                
            case 5:
                // TCP
                filter_str = strdup("tcp");
                printf("\n[C-Shark] Filter applied: TCP traffic\n");
                return filter_str;
                
            case 6:
                // UDP
                filter_str = strdup("udp");
                printf("\n[C-Shark] Filter applied: UDP traffic\n");
                return filter_str;
                
            case 7:
                // Cancel
                printf("\n[C-Shark] Filter cancelled.\n");
                return NULL;
                
            default:
                printf("[C-Shark] Invalid selection. Please choose 1-7.\n");
                break;
        }
    }
}

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
