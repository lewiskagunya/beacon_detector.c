#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_TRACKED_IPS 100
#define JITTER_THRESHOLD 100000 // 0.1 seconds (100,000 microseconds)
#define BEACON_LIMIT 5          // How many matches before we alert

// --- Data Structures ---
struct beacon_record {
    char ip_addr[16];
    struct timeval last_seen;
    long last_delta;
    int confidence_score;
};

struct beacon_record tracker[MAX_TRACKED_IPS];
int total_ips_tracked = 0;

// --- Logic: The "Brain" of the Detector ---
void process_packet_timing(char* src_ip) {
    struct timeval now;
    gettimeofday(&now, NULL);

    for (int i = 0; i < total_ips_tracked; i++) {
        if (strcmp(tracker[i].ip_addr, src_ip) == 0) {
            // 1. Calculate Time Difference (Delta)
            long seconds = now.tv_sec - tracker[i].last_seen.tv_sec;
            long useconds = now.tv_usec - tracker[i].last_seen.tv_usec;
            long current_delta = (seconds * 1000000) + useconds;

            // 2. Compare to the previous Delta to find a pattern
            long variance = current_delta - tracker[i].last_delta;
            if (variance < 0) variance = -variance;

            if (tracker[i].last_delta > 0 && variance < JITTER_THRESHOLD) {
                tracker[i].confidence_score++;
                if (tracker[i].confidence_score >= BEACON_LIMIT) {
                    printf("\n[!!!] ALERT: BEACON DETECTED [!!!]\n");
                    printf("Source: %s | Interval: %ld ms\n", src_ip, current_delta / 1000);
                }
            } else {
                tracker[i].confidence_score = 0; // Reset if the timing breaks
            }

            // 3. Update memory for next packet
            tracker[i].last_seen = now;
            tracker[i].last_delta = current_delta;
            return;
        }
    }

    // New IP? Add it to the tracking list
    if (total_ips_tracked < MAX_TRACKED_IPS) {
        strcpy(tracker[total_ips_tracked].ip_addr, src_ip);
        tracker[total_ips_tracked].last_seen = now;
        tracker[total_ips_tracked].last_delta = 0;
        tracker[total_ips_tracked].confidence_score = 0;
        total_ips_tracked++;
    }
}

// --- Main: The Raw Socket Engine ---
int main() {
    int sock_raw;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(65536);

    // Create Raw Socket (Layer 2)
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    printf("Beacon Detector Engine Started... Monitoring Traffic.\n");

    while (1) {
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0) continue;

        // Extract IP Header (Skipping 14 bytes of Ethernet Header)
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        if (iph->protocol == IPPROTO_ICMP || iph->protocol == IPPROTO_TCP) {
            struct in_addr ip_addr;
            ip_addr.s_addr = iph->saddr;
            char *src_ip = inet_ntoa(ip_addr);
            
            // Run the timing analysis
            process_packet_timing(src_ip);
        }
    }
    close(sock_raw);
    return 0;
}
