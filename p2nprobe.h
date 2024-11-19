/**
 * @author Boris Hatala xhatal02
 * @file p2nprobe.h
 * @date 18.11.2024
 */

#ifndef P2NPROBE_H
#define P2NPROBE_H

#include <iostream>
#include <regex>

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <chrono>

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

//map for storing activeFlows where packets can be agregated
map<string, Flow> activeFlows;
//map for storing flows that are waiting to be sent
map<string, Flow> flowsBuffer;

bool firstPacket;
//reference system time
uint32_t reference_time;

//active and inactive timeouts
int activeTO;
int inactiveTO;

//collector ip and port
const char* collector_ip;
uint16_t collector_port;

unsigned int record_count;
size_t flow_sequence;

//start time of the exporter program
std::chrono::system_clock::time_point program_start;


// NetFlow v5 Header (24 bytes)
struct NetFlowV5Header {
    uint16_t version;           // Version of NetFlow (always 5)
    uint16_t count;             // Number of flow records in the packet (1-30)
    uint32_t sysUptime;         // Current time in milliseconds since the device started
    uint32_t unixSecs;          // Current Unix time (seconds since 1970)
    uint32_t unixNsecs;         // Residual nanoseconds of the current second
    uint32_t flowSequence;      // Sequence counter of total activeFlows exported
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
    uint16_t pad2;              // Padding
};

// Full NetFlow v5 packet (header + up to 30 records)
struct NetFlowV5Packet {
    struct NetFlowV5Header header;
    struct NetFlowV5Record records[30];  // Up to 30 flow records
};

#define MAX_NETFLOW_PACKET 30
#define BUFFFER_SIZE 1024

#define NETFLOW_V5_HEADER_SIZE 24
#define NETFLOW_V5_RECORD_SIZE 48
#define NETFLOW_V5_MAX_RECORDS 30

/**
 * @brief Parses command line arguments and checks their validity
 * 
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param filename Reference to the filename string.
 * @param collector_ip Reference to the collector IP string.
 * @param collector_port Reference to the collector port string.
 * @param activeTO Reference to the active timeout.
 * @param inactiveTO Reference to the inactive timeout.
 */
void parseArgs(int argc, char *argv[], string &filename, string &collector_ip, string &collector_port, int &activeTO, int& inactiveTO);

/**
 * @brief Validates an IP address.
 * 
 * @param ip The IP address string.
 * @return true if the IP address is valid, false otherwise.
 */
bool isValidIpAddress(const std::string &ip);

/**
 * @brief Validates a port.
 * 
 * @param port The port string.
 * @return true if the port is valid, false otherwise.
 */
bool isValidPort(const std::string &port);

/**
 * @brief Callback function for processing packets, parses only TCP packets, sends TCP packets to packet handler.
 * 
 * @param userData User data.
 * @param pkthdr Packet header.
 * @param packet Packet data.
 */
void callback(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/**
 * @brief Checks for active flow timeouts.
 * 
 * @param current_time The current time in milliseconds.
 */
void checkTimeouts(uint32_t current_time);

/**
 * @brief Checks for timeouts before processing a new packet so that it will add it to correct flow, or create a new one.
 *        Passes it to agregateFlows.  
 *  
 * @param ip_header IP header.
 * @param tcp_header TCP header.
 * @param pkthdr Packet header.
 * @param current_time The current time in milliseconds.
 * @param packet Reference to the NetFlow v5 packet.
 * @param record_count Reference to the record count.
 * @param flow_sequence Reference to the flow sequence.
 */
void handlePacket(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr, uint32_t current_time, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence);

/**
 * @brief Aggregates flows based on packet data.
 * 
 * @param ip_header IP header.
 * @param tcp_header TCP header.
 * @param pkthdr Packet header.
 */
void agregateFlows(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr);

/**
 * @brief Creates a flow key from IP addresses and ports.
 * 
 * @param src_ip Source IP address.
 * @param dst_ip Destination IP address.
 * @param src_port Source port.
 * @param dst_port Destination port.
 * @return The flow key string.
 */
string createFlowKey(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port);

/**
 * @brief Initializes a NetFlow v5 packet.
 * 
 * @param packet Reference to the NetFlow v5 packet.
 * @param flow_sequence The flow sequence number.
 */
void initNetFlowV5Packet(NetFlowV5Packet &packet, size_t flow_sequence);

/**
 * @brief Populates a NetFlow v5 packet with flow data.
 * 
 * @param packet Reference to the NetFlow v5 packet.
 * @param record_count Reference to the record count.
 * @param flow The flow data.
 */
void populateNetFlowV5Packet(NetFlowV5Packet &packet, unsigned int &record_count, const Flow &flow);

/**
 * @brief Populates and sends NetFlow v5 packets if needed.
 * 
 * @param collector_ip Collector IP address.
 * @param collector_port Collector port.
 * @param flows Map of flows.
 * @param packet Reference to the NetFlow v5 packet.
 * @param record_count Reference to the record count.
 * @param flow_sequence Reference to the flow sequence.
 */
void populateNetFlowV5(const char *collector_ip, uint16_t collector_port, map<string, Flow> &flows, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence);

/**
 * @brief Sends a NetFlow v5 packet to the collector.
 * 
 * @param collector_ip Collector IP address.
 * @param collector_port Collector port.
 * @param packet The NetFlow v5 packet.
 */
void sendNetFlowV5(const char* collector_ip, uint16_t collector_port, const NetFlowV5Packet &packet);

/**
 * @brief Moves active flows to the buffer.
 */
void moveActiveFlowsToBuffer();

/**
 * @brief Sends any remaining NetFlow v5 records.
 * 
 * @param packet Reference to the NetFlow v5 packet.
 */
void sendRest(NetFlowV5Packet &packet);

#endif