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
#include <unistd.h>


#include <err.h>
#include <errno.h>

#include <stdint.h>
#include <cstdlib>
#include <vector>
#include <string>
#include <string.h>
#include <map>

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

//map for storing flows
map<string, Flow> flows;

// NetFlow v5 Header (24 bytes)
struct NetFlowV5Header {
    uint16_t version;           // Version of NetFlow (always 5)
    uint16_t count;             // Number of flow records in the packet (1-30)
    uint32_t sysUptime;         // Current time in milliseconds since the device started
    uint32_t unixSecs;          // Current Unix time (seconds since 1970)
    uint32_t unixNsecs;         // Residual nanoseconds of the current second
    uint32_t flowSequence;      // Sequence counter of total flows exported
    uint8_t engineType;         // Type of flow-switching engine (e.g., router, switch)
    uint8_t engineID;           // ID of the flow-switching engine
    uint16_t samplingInterval;  // Sampling mode and interval
};

// NetFlow v5 Flow Record (48 bytes)
struct NetFlowV5Record {
    uint32_t srcAddr;           // Source IP address
    uint32_t dstAddr;           // Destination IP address
    uint32_t nextHop;           // IP address of the next hop router
    uint16_t inputInterface;    // SNMP index of the input interface
    uint16_t outputInterface;   // SNMP index of the output interface
    uint32_t packets;           // Total number of packets in the flow
    uint32_t bytes;             // Total number of bytes in the flow
    uint32_t first;             // Uptime in milliseconds at the start of the flow
    uint32_t last;              // Uptime in milliseconds at the end of the flow
    uint16_t srcPort;           // Source TCP/UDP port or ICMP type/code
    uint16_t dstPort;           // Destination TCP/UDP port or ICMP type/code
    uint8_t pad1;               // Padding (unused)
    uint8_t tcpFlags;           // Cumulative OR of all TCP flags seen in the flow
    uint8_t protocol;           // IP protocol (TCP = 6, UDP = 17, ICMP = 1)
    uint8_t tos;                // Type of Service (ToS)
    uint16_t srcAS;             // Source autonomous system number
    uint16_t dstAS;             // Destination autonomous system number
    uint8_t srcMask;            // Source subnet mask in CIDR format
    uint8_t dstMask;            // Destination subnet mask in CIDR format
    uint16_t pad2;              // Padding (unused)
};

// Full NetFlow v5 packet (header + up to 30 records)
struct NetFlowV5Packet {
    struct NetFlowV5Header header;
    struct NetFlowV5Record records[30];  // Up to 30 flow records
};

#define MAX_NETFLOW_PACKET 30
#define COLL_IP "127.0.0.1"
#define COLL_PORT 2055
#define BUFFFER_SIZE 1024

#define NETFLOW_V5_HEADER_SIZE 24
#define NETFLOW_V5_RECORD_SIZE 48
#define NETFLOW_V5_MAX_RECORDS 30

//handle TCP packets
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

//agregate packets into flows based on key
void agregateFlows(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr);

//create a symmetrical key so that it works for bidirectional flows
string createFlowKey(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port);

void printFlows();

#endif