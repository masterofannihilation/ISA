/**
 * @file p2nprobe.cpp
 * @author Boris Hatala xhatal02
 * @date 18.11.2024
 */

#include "p2nprobe.h"
    
void printNetFlowV5Packet(const NetFlowV5Packet &packet) {
    // Print header information
    std::cout << "NetFlow V5 Packet Header:" << std::endl;
    std::cout << "  sysUptime: " << ntohl(packet.header.sysUptime) << std::endl;
    std::cout << "  unixSecs: " << ntohl(packet.header.unixSecs) << std::endl;
    std::cout << "  unixNsecs: " << ntohl(packet.header.unixNsecs) << std::endl;
    std::cout << "  flowSequence: " << ntohl(packet.header.flowSequence) << std::endl;
    std::cout << "  count: " << ntohs(packet.header.count) << std::endl;

    // Print each record
    for (int i = 0; i < ntohs(packet.header.count); ++i) {
        const NetFlowV5Record &record = packet.records[i];
        std::cout << "Record " << i + 1 << ":" << std::endl;
        std::cout << "  srcAddr: " << inet_ntoa({record.srcAddr}) << std::endl;
        std::cout << "  dstAddr: " << inet_ntoa({record.dstAddr}) << std::endl;
        std::cout << "  srcPort: " << ntohs(record.srcPort) << std::endl;
        std::cout << "  dstPort: " << ntohs(record.dstPort) << std::endl;
        std::cout << "  protocol: " << static_cast<int>(record.protocol) << std::endl;
        std::cout << "  bytes: " << ntohl(record.bytes) << std::endl;
        std::cout << "  first: " << ntohl(record.first) << std::endl;
        std::cout << "  last: " << ntohl(record.last) << std::endl;
    }
}

void printFlows() {
    std::cout << "Current Flows:\n";
    if(flowsBuffer.size() != 0) {
        for (const auto &entry : flowsBuffer) {
            const Flow &flow = entry.second;
            std::cout << "Flow Key: " << entry.first << "\n";
            std::cout << "Source IP: " << inet_ntoa(flow.src_ip) << ":" << flow.src_port << "\n";
            std::cout << "Destination IP: " << inet_ntoa(flow.dst_ip) << ":" << flow.dst_port << "\n";
            std::cout << "Protocol: " << (flow.protocol == IPPROTO_TCP ? "TCP" : "Unknown") << "\n";
            std::cout << "Packet Count: " << flow.packet_count << "\n";
            std::cout << "Byte Count: " << flow.byte_count << "\n";
            std::cout << "Flow Start Time: " << flow.flow_start << "\n";
            std::cout << "Flow End Time: " << flow.flow_end << "\n";
            std::cout << "Flow Duration: " << (flow.flow_end - flow.flow_start) / 1000.0 << " seconds\n";
            std::cout << "--------------------------------------\n";
        }
    }
}

bool isValidIpAddress(const std::string &ip) {
    std::regex ipRegex("^[a-zA-Z0-9.@]+$");
    return std::regex_match(ip, ipRegex);
}

bool isValidPort(const std::string &port) {
    if (port.empty() || port.length() > 5) return false;
    for (char c : port) {
        if (!isdigit(c)) return false;
    }
    int portNum = std::stoi(port);
    return portNum > 0 && portNum <= 65535;
}

void parseArgs(int argc, char *argv[], string &filename, string &coll_ip, string &coll_port, int &activeTO, int& inactiveTO) {
    activeTO = 60;
    inactiveTO = 60;
    int opt;
    while((opt = getopt(argc, argv, "a:i:")) != -1){
        switch (opt)
        {
        case 'a':
            activeTO = stoi(optarg);
            break;
        case 'i':
            inactiveTO = stoi(optarg);
            break;        
        case '?':
                cerr << "Unknown option: " << char(optopt) << "\n";
                break;
        default:
            break;
        }
    }

    for (int i = optind; i < argc; i++) {
        string arg = argv[i];
        //look for pcap file
        if(arg.find(".pcap") != std::string::npos) {
            filename = argv[i];
        }
        //find address and port based on ':'
        if(arg.find(':') != std::string::npos) {
            size_t colonPos = arg.find(':');
            coll_ip = arg.substr(0,colonPos);
            coll_port = arg.substr(colonPos + 1);
        }
    }
    
    
    if(filename.empty() || coll_ip.empty() || coll_port.empty()) {
        cerr << "Missing arguments" << endl;
        cerr << "Usage: ./p2nprobe [-a activeTO] [-i inactiveTO] <pcap_file> <collector_ip:collector_port>" << endl;
        exit(1);
    }

    if (!isValidIpAddress(coll_ip)) {
        cerr << "Invalid IP address format" << endl;
        exit(1);
    }

    if (!isValidPort(coll_port) || stoi(coll_port) > 65535 || stoi(coll_port) <= 0) {
        cerr << "Invalid port format" << endl;
        exit(1);
    }

    collector_ip = coll_ip.c_str();
    collector_port = static_cast<uint16_t>(stoi(coll_port));
}

string createFlowKey(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port) {
    return string(inet_ntoa(src_ip)) + ":" + std::to_string(src_port) + "," + string(inet_ntoa(dst_ip)) + ":" + to_string(dst_port);
}

void callback(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    NetFlowV5Packet *packetPtr = reinterpret_cast<NetFlowV5Packet*>(userData);

    // Get the current time of a packet in milliseconds
    uint32_t current_time = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

    //parse the Ethernet header
    struct ether_header *eth_header = (struct ether_header *) packet;
    //check if packet is ip
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        //parse the IP header
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        //check if packet is TCP
        if (ip_header->ip_p == IPPROTO_TCP) {
            //parse the TCP header, set the offset
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));          

            //create a new flow or update an exisitng one
            handlePacket(ip_header, tcp_header, pkthdr, current_time, *packetPtr, record_count, flow_sequence);
        }
    }
}

void checkTimeouts(uint32_t current_time) {
    for (auto it = activeFlows.begin(); it != activeFlows.end(); ) {
        Flow &flow = it->second;
        if (current_time - flow.flow_end >= static_cast<uint32_t>(inactiveTO) * 1000) {
            flowsBuffer[it->first] = flow;
            it = activeFlows.erase(it);
        }
        else if (current_time - flow.flow_start >= static_cast<uint32_t>(activeTO) * 1000) {
            flowsBuffer[it->first] = flow;
            it = activeFlows.erase(it);
        } 
        else
            ++it;
    }
}

void handlePacket(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr, uint32_t current_time, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence) {
    // Check for timeouts before processing the new packet
    checkTimeouts(current_time);

    //init the very fist packet
    if(firstPacket) {
        initNetFlowV5Packet(packet, flow_sequence);
        firstPacket = false;
    }

    // if there are any flows in the buffer, add them to netflow v5 packet
    if(flowsBuffer.size() > 0) {
        populateNetFlowV5(collector_ip, collector_port, flowsBuffer, packet, record_count, flow_sequence);
    }

    // Aggregate flows
    agregateFlows(ip_header, tcp_header, pkthdr);
}

void agregateFlows(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr) {
    // Generate a flow key using the IP addresses, ports and start time to uniquely identify the flow
    string key = createFlowKey(ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    // Check if the flow already exists
    if (activeFlows.find(key) != activeFlows.end()) {
        // Update the existing flow
        activeFlows[key].packet_count++;
        // mimnus 14 bytes for the ethernet header
        activeFlows[key].byte_count += pkthdr->len - 14;
        activeFlows[key].flow_end = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;
    }
    else {
        // Create a new flow
        Flow newFlow;
        newFlow.src_ip = ip_header->ip_src;
        newFlow.dst_ip = ip_header->ip_dst;
        newFlow.src_port = ntohs(tcp_header->th_sport);
        newFlow.dst_port = ntohs(tcp_header->th_dport);
        newFlow.protocol = ip_header->ip_p;
        newFlow.packet_count = 1;
        // mimnus 14 bytes for the ethernet header
        newFlow.byte_count = pkthdr->len - 14;
        newFlow.flow_start = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;
        newFlow.flow_end = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

        // Add the new flow to the activeFlows table
        activeFlows[key] = newFlow;
    }
}

void sendNetFlowV5(const char* collector_ip, uint16_t collector_port, const NetFlowV5Packet &packet){
    //Create a UDP socket
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( udpSocket< 0){
        cerr << "Failed to create socket" << endl;
    }

    // Set up the address of the collector
    struct sockaddr_in collAddr;
    memset(&collAddr, 0, sizeof(collAddr));
    collAddr.sin_family = AF_INET;
    collAddr.sin_port = htons(collector_port);
    inet_pton(AF_INET, collector_ip, &collAddr.sin_addr);

    // Serialize the packet into a buffer
    uint8_t buffer[sizeof(NetFlowV5Packet)];
    memcpy(buffer, &packet, sizeof(NetFlowV5Packet));

    // Send packet to collector
    ssize_t sentBytes = sendto(udpSocket, buffer, sizeof(NetFlowV5Packet), 0, (const struct sockaddr*)&collAddr, sizeof(collAddr));
    if (sentBytes < 0) {
        perror("sendto failed");
    } 
    else {
        cout << "Sent " << sentBytes << " bytes to " << collector_ip << ":" << collector_port << endl;
    }

    close(udpSocket);
}

void populateNetFlowV5Packet(NetFlowV5Packet &packet, unsigned int &record_count, const Flow &flow) {
    NetFlowV5Record &record = packet.records[record_count];
    record.srcAddr = flow.src_ip.s_addr;
    record.dstAddr = flow.dst_ip.s_addr;
    record.packets = htonl(flow.packet_count);
    record.bytes = htonl(flow.byte_count);
    record.srcPort = htons(flow.src_port);
    record.dstPort = htons(flow.dst_port);
    record.protocol = flow.protocol;

    record.nextHop = 0;
    record.inputInterface = 0;
    record.outputInterface = 0;
    record.pad1 = 0;
    record.tcpFlags = 0;
    record.tos = 0;
    record.srcAS = 0;
    record.dstAS = 0;
    record.srcMask = 0;
    record.dstMask = 0;
    record.pad2 = 0;

    // Calculate the difference between flow_start and program_start in milliseconds    
    record.first = htonl(flow.flow_start - std::chrono::duration_cast<std::chrono::milliseconds>(program_start.time_since_epoch()).count());
    record.last = htonl(flow.flow_end - std::chrono::duration_cast<std::chrono::milliseconds>(program_start.time_since_epoch()).count());

    record_count++;
}

void sendNetFlowV5IfNeeded(const char *collector_ip, uint16_t collector_port, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence) {
    if (record_count == MAX_NETFLOW_PACKET) {
        packet.header.count = htons(record_count);
        sendNetFlowV5(collector_ip, collector_port, packet);
        flow_sequence += MAX_NETFLOW_PACKET;
        record_count = 0;
        initNetFlowV5Packet(packet, flow_sequence);
    }
}

void populateNetFlowV5(const char *collector_ip, uint16_t collector_port, map<string, Flow> &flows, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence) {
    // Fill records with flows from the map
    for (auto it = flows.begin(); it != flows.end();)
    {
        const Flow &flow = it -> second;
        populateNetFlowV5Packet(packet, record_count, flow);
        packet.header.count = htons(record_count);

        // Remove the flow from the buffer
        it = flows.erase(it);

        // Check if the packet is full
        sendNetFlowV5IfNeeded(collector_ip, collector_port, packet, record_count, flow_sequence);
    }
}

void initNetFlowV5Packet(NetFlowV5Packet &packet, size_t flow_sequence) {
    //zero out whole header of packet and set it
    memset(&packet, 0, sizeof(packet));
    packet.header.version = htons(5);

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - program_start).count();
    packet.header.sysUptime = htonl(duration);

    packet.header.unixSecs = htonl(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    packet.header.unixNsecs = htonl(now_ns % 1000000000);

    packet.header.flowSequence = htonl(flow_sequence);
}

void moveActiveFlowsToBuffer() {
    for (auto it = activeFlows.begin(); it != activeFlows.end(); ) {
        flowsBuffer[it->first] = it->second;
        it = activeFlows.erase(it);
    }
}

void sendRest(NetFlowV5Packet &packet) {
    // Move reamining active flows to flowsBuffer
    moveActiveFlowsToBuffer();

    // Populate final nfv5 packet and send it to collector
    if (flowsBuffer.size() > 0)
    {
        populateNetFlowV5(collector_ip, collector_port, flowsBuffer, packet, record_count, flow_sequence);
    }

    // Send any remaining records
    if (record_count > 0)
    {
        packet.header.count = htons(record_count);
        sendNetFlowV5(collector_ip, collector_port, packet);
    }
}

int main(int argc, char *argv[]) {
    program_start = std::chrono::system_clock::now();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    string filename;
    string collIp;
    string collPort;

    //parse command line arguments and convert them into needed types
    parseArgs(argc, argv, filename, collIp, collPort, activeTO, inactiveTO);
    const char* pcap_filename = filename.c_str();   

    //open pcap file
    handle = pcap_open_offline(pcap_filename, errbuf);
    if(handle == NULL){
        cerr << "Error opening pcap file" << errbuf << endl;
        return 1;  
    }

    // Initialize NetFlowV5 packet
    NetFlowV5Packet packet;
    record_count = 0;
    flow_sequence = 0;
    firstPacket = true;

    // process individual packets from pcap file in packet handler
    if(pcap_loop(handle, 0, callback, (u_char*)&packet) < 0 ) {
        cerr << "Error reading packets from pcap file" << errbuf << endl;
        pcap_close(handle);
        return 1;
    }

    // Send any remaining flows
    sendRest(packet);

    pcap_close(handle);

    return 0;
}
