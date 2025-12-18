// ############## LLM Generated Code Begins ##############
#ifndef CAPTURE_H
#define CAPTURE_H

// Main packet capture function without filter
void start_packet_capture(const char *iface_name);

// Packet capture with BPF filter
void start_packet_capture_filtered(const char *iface_name, const char *filter);

// Enable/disable packet storage during capture
void capture_set_storage_enabled(int enabled);

#endif

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
