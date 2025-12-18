// ############## LLM Generated Code Begins ##############
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "interface.h"

pcap_if_t* get_all_interfaces(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Error finding devices: %s\n", errbuf);
        return NULL;
    }
    return alldevs;
}

void print_interfaces(pcap_if_t *alldevs) {
    printf("\n[C-Shark] Searching for available interfaces... Found!\n\n");
    int idx = 1;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%2d. %s", idx, dev->name);
        if (dev->description)
            printf(" (%s)", dev->description);
        printf("\n");
        idx++;
    }
    printf("\nSelect an interface to sniff (1-%d) or press Ctrl+D to exit:\n", idx - 1);
}

pcap_if_t* get_interface_by_index(pcap_if_t *alldevs, int index) {
    int count = 1;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next, count++) {
        if (count == index) return dev;
    }
    return NULL;
}

// ############## LLM Generated Code Ends ################
