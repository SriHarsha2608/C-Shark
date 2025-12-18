// ############## LLM Generated Code Begins ##############
#ifndef INTERFACE_H
#define INTERFACE_H

#include <pcap.h>

pcap_if_t* get_all_interfaces(void);
void print_interfaces(pcap_if_t *alldevs);
pcap_if_t* get_interface_by_index(pcap_if_t *alldevs, int index);

#endif

// ############## LLM Generated Code Ends ################
