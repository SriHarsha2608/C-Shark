// ############## LLM Generated Code Begins ##############
// capture.c
#define _POSIX_C_SOURCE 200809L  // For modern POSIX features

#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#ifndef u_char
typedef unsigned char u_char;
#endif

#ifndef u_int
typedef unsigned int u_int;
#endif

#ifndef u_short
typedef unsigned short u_short;
#endif

#include <pcap.h>
#include "capture.h"
#include "storage.h"
#include "ethernet.h"
#include "network.h"
#include "transport.h"
#include "application.h"

static pcap_t *g_handle = NULL;
static volatile sig_atomic_t g_break_requested = 0;
static int g_storage_enabled = 1;  // Storage enabled by default

static void sigint_handler(int signo) {
    (void)signo;
    g_break_requested = 1;
    if (g_handle)
        pcap_breakloop(g_handle);
}

void capture_set_storage_enabled(int enabled) {
    g_storage_enabled = enabled;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    static unsigned long id = 0;
    id++;

    // Store packet if storage is enabled
    if (g_storage_enabled) {
        if (!storage_add_packet(bytes, h->caplen, &h->ts)) {
            if (storage_get_count() == MAX_PACKETS) {
                printf("\n[C-Shark] WARNING: Storage limit reached (%d packets). No longer storing.\n", MAX_PACKETS);
                g_storage_enabled = 0;  // Disable storage for this session
            }
        }
    }

    printf("\n-----------------------------------------\n");
    printf("Packet #%lu | Timestamp: %ld.%06ld | Length: %u bytes\n",
           id, (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->caplen);
    
    // Parse Ethernet (Layer 2)
    uint16_t ethertype;
    int eth_len = parse_ethernet(bytes, h->caplen, &ethertype);
    if (eth_len < 0) return;
    
    const u_char *l3_data = bytes + eth_len;
    int l3_len = h->caplen - eth_len;
    
    // Parse Network Layer (Layer 3)
    if (ethertype == ETHERTYPE_ARP) {
        parse_arp(l3_data, l3_len);
        return;
    }
    
    uint8_t protocol = 0;
    const u_char *l4_data = NULL;
    int l4_len = 0;
    
    if (ethertype == ETHERTYPE_IP) {
        l4_len = parse_ipv4(l3_data, l3_len, &protocol, &l4_data);
    } else if (ethertype == ETHERTYPE_IPV6) {
        l4_len = parse_ipv6(l3_data, l3_len, &protocol, &l4_data);
    } else {
        return;  // Unknown ethertype
    }
    
    if (l4_len <= 0 || !l4_data) return;
    
    // Parse Transport Layer (Layer 4)
    uint16_t sport = 0, dport = 0;
    int l7_offset = 0;
    
    if (protocol == IPPROTO_TCP) {
        l7_offset = parse_tcp(l4_data, l4_len, &sport, &dport);
    } else if (protocol == IPPROTO_UDP) {
        l7_offset = parse_udp(l4_data, l4_len, &sport, &dport);
    } else {
        return;  // Unknown protocol
    }
    
    if (l7_offset < 0) return;
    
    // Parse Application Layer / Payload (Layer 7)
    const u_char *payload = l4_data + l7_offset;
    int payload_len = l4_len - l7_offset;
    
    if (payload_len > 0) {
        parse_payload(payload, payload_len, sport, dport);
    }
}

void start_packet_capture(const char *iface_name) {
    start_packet_capture_filtered(iface_name, NULL);
}

void start_packet_capture_filtered(const char *iface_name, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net=0, mask=0;
    g_handle = NULL;

    // Clear previous session and prepare for new one
    storage_clear();
    g_storage_enabled = 1;  // Re-enable storage for new session

    if (filter) {
        printf("\n[C-Shark] Starting filtered capture on '%s'\n", iface_name);
        printf("[C-Shark] Filter: %s\n", filter);
    } else {
        printf("\n[C-Shark] Starting live capture on '%s'\n", iface_name);
    }
    printf("[C-Shark] Storage: Enabled (max %d packets)\n", MAX_PACKETS);
    printf("[C-Shark] Press Ctrl+C or Ctrl+D to stop capture.\n\n");

    pcap_lookupnet(iface_name, &net, &mask, errbuf);
    g_handle = pcap_open_live(iface_name, 65535, 1, 1000, errbuf);
    if (!g_handle) {
        fprintf(stderr, "[C-Shark] Error opening device %s: %s\n", iface_name, errbuf);
        return;
    }

    // Apply BPF filter if provided
    if (filter) {
        struct bpf_program fp;
        if (pcap_compile(g_handle, &fp, filter, 0, net) == -1) {
            fprintf(stderr, "[C-Shark] Error compiling filter: %s\n", pcap_geterr(g_handle));
            pcap_close(g_handle);
            g_handle = NULL;
            return;
        }
        if (pcap_setfilter(g_handle, &fp) == -1) {
            fprintf(stderr, "[C-Shark] Error setting filter: %s\n", pcap_geterr(g_handle));
            pcap_freecode(&fp);
            pcap_close(g_handle);
            g_handle = NULL;
            return;
        }
        pcap_freecode(&fp);
    }

    struct sigaction sa = {0};
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    g_break_requested = 0;
    
    // Custom capture loop that monitors both stdin and pcap
    int pcap_fd = pcap_get_selectable_fd(g_handle);
    int stdin_fd = fileno(stdin);
    int eof_detected = 0;
    int error_occurred = 0;
    
    // Set stdin to non-blocking mode
    int stdin_flags = fcntl(stdin_fd, F_GETFL, 0);
    fcntl(stdin_fd, F_SETFL, stdin_flags | O_NONBLOCK);
    
    while (!g_break_requested && !eof_detected) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(pcap_fd, &readfds);
        FD_SET(stdin_fd, &readfds);
        
        int max_fd = (pcap_fd > stdin_fd) ? pcap_fd : stdin_fd;
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms timeout
        
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) continue;  // Interrupted by signal, retry
            error_occurred = 1;
            break;
        }
        
        // Check if stdin has input (or EOF)
        if (FD_ISSET(stdin_fd, &readfds)) {
            char buf[1];
            ssize_t n = read(stdin_fd, buf, 1);
            if (n == 0) {
                // EOF detected (Ctrl+D) - exit the program
                eof_detected = 1;
                printf("\n[C-Shark] Ctrl+D detected. Exiting...\n");
            } else if (n > 0) {
                // User typed something; just ignore it during capture
            }
        }
        
        // Check if pcap has packets
        if (FD_ISSET(pcap_fd, &readfds)) {
            int pcap_ret = pcap_dispatch(g_handle, -1, packet_handler, NULL);
            if (pcap_ret == PCAP_ERROR) {
                error_occurred = 1;
                break;
            }
        }
    }
    
    // Restore stdin to blocking mode
    fcntl(stdin_fd, F_SETFL, stdin_flags);

    if (error_occurred)
        fprintf(stderr, "[C-Shark] Capture error: %s\n", pcap_geterr(g_handle));
    else if (g_break_requested)
        printf("\n[C-Shark] Capture stopped (Ctrl+C)\n");
    
    // Display storage stats if not exiting
    if (!eof_detected) {
        int stored_count = storage_get_count();
        printf("[C-Shark] Session complete: %d packet%s stored in memory.\n", 
               stored_count, stored_count == 1 ? "" : "s");
    }

    pcap_close(g_handle);
    g_handle = NULL;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);
    
    // Exit program if Ctrl+D was pressed
    if (eof_detected) {
        storage_cleanup();
        exit(0);
    }
}

// ############## LLM Generated Code Ends ################
############## LLM Generated Code Ends ################
