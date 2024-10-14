#ifndef P2NPROBE_H
#define P2NPROBE_H

#include <iostream>

#include <pcap.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>

#include <stdint.h>
#include <cstdlib>
#include <vector>

using namespace std;

struct Flow {
    struct in_addr src_ip;        // Source IP address
    struct in_addr dst_ip;        // Destination IP address
    uint16_t src_port;            // Source port number
    uint16_t dst_port;            // Destination port number
    uint32_t packet_count;        // Total packet count for the flow
    uint32_t byte_count;          // Total byte count for the flow
    uint8_t protocol;             // Protocol (e.g., TCP)
    uint32_t flow_start;          // Flow start timestamp (could use time_t)
    uint32_t flow_end;            // Flow end timestamp (could use time_t)
};

vector<Flow> flows;

//handle TCP packets only
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void agregateFlows(Flow &flow);

#endif