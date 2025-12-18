// ############## LLM Generated Code Begins ##############
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include "interface.h"
#include "capture.h"
#include "filter.h"
#include "storage.h"
#include "util.h"

int main(void) {
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    // Initialize storage system
    storage_init();

    pcap_if_t *alldevs = get_all_interfaces();
    if (!alldevs) {
        printf("[C-Shark] No interfaces found. Exiting.\n");
        storage_cleanup();
        return 0;
    }

    while (1) {
        print_interfaces(alldevs);
        char *choice_s = read_input_line("> ");
        if (!choice_s) {   // Ctrl+D
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            pcap_freealldevs(alldevs);
            storage_cleanup();
            break;
        }

        int sel = atoi(choice_s);
        free(choice_s);

        pcap_if_t *selected = get_interface_by_index(alldevs, sel);
        if (!selected) {
            printf("[C-Shark] Invalid selection. Try again.\n");
            continue;
        }

        // Main menu for selected interface
        while (1) {
            printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", selected->name);
            printf("1. Start Sniffing (All Packets)\n");
            printf("2. Start Sniffing (With Filters)\n");
            printf("3. Inspect Last Session\n");
            printf("4. Exit C-Shark\n");

            char *opt = read_input_line("\nSelect an option (1-4): ");
            if (!opt) {
                printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
                pcap_freealldevs(alldevs);
                storage_cleanup();
                return 0;
            }

            if (strcmp(opt, "1") == 0) {
                free(opt);
                start_packet_capture(selected->name);
            } else if (strcmp(opt, "2") == 0) {
                free(opt);
                char *filter = get_filter_from_user();
                if (filter) {
                    start_packet_capture_filtered(selected->name, filter);
                    free(filter);
                }
            } else if (strcmp(opt, "3") == 0) {
                free(opt);
                storage_inspect_interactive();
            } else if (strcmp(opt, "4") == 0) {
                free(opt);
                printf("[C-Shark] Exiting...\n");
                pcap_freealldevs(alldevs);
                storage_cleanup();
                return 0;  // Exit the program
            } else {
                printf("[C-Shark] Option not implemented or invalid.\n");
                free(opt);
            }
        }
    }

    storage_cleanup();
    return 0;
}

// ############## LLM Generated Code Ends ################
