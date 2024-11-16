#include "p2nprobe.h"

void printNetFlowV5Packet(const NetFlowV5Packet &packet) {
    cout << "kokot" << endl;
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

void parseArgs(int argc, char *argv[], string &filename, string &collector_ip, string &collector_port, int &activeTO, int& inactiveTO) {
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
        else if(arg.find(':') != std::string::npos) {
            size_t colonPos = arg.find(':');
            collector_ip = arg.substr(0,colonPos);
            collector_port = arg.substr(colonPos + 1);
        }
        else{
            cerr << "Missing arguments" << endl;
        }
    }
}

string createFlowKey(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port) {
    return string(inet_ntoa(src_ip)) + ":" + std::to_string(src_port) + "," + string(inet_ntoa(dst_ip)) + ":" + to_string(dst_port);
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    NetFlowV5Packet *packetPtr = reinterpret_cast<NetFlowV5Packet*>(userData);
    // static size_t record_count = 0;
    static size_t flow_sequence = 0;

    if (reference_time == 0) {
        reference_time = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;
    }
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
        if (flow.dst_port == 50046 || flow.src_port == 50046) {
            // std::cout << "Current Time: " << current_time << " ms, Flow End Time: " << flow.flow_end << " ms" << std::endl;
        }
        if (current_time - flow.flow_end > static_cast<uint32_t>(inactiveTO) * 1000) {
            // cout << "INACTIVE TIMEOUT" << endl;
            flowsBuffer[it->first] = flow;
            it = activeFlows.erase(it);
        }
        // Check for active timeout
        else if (current_time - flow.flow_start > static_cast<uint32_t>(activeTO) * 1000) {
            // cout << "ACTIVE TIMEOUT" << endl;
            flowsBuffer[it->first] = flow;
            it = activeFlows.erase(it);
        } 
        else
            ++it;
    }
    // printFlows();    
}

void handlePacket(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr, uint32_t current_time, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence) {
    // Check for timeouts before processing the new packet
    checkTimeouts(current_time);

    // if there are any flows in the buffer, send them
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
        activeFlows[key].byte_count += pkthdr->len;
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
        newFlow.byte_count = pkthdr->len;
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
    record.first = htonl(flow.flow_start - reference_time);
    record.last = htonl(flow.flow_end - reference_time);
    record_count++;
}

void sendNetFlowV5IfNeeded(const char *collector_ip, uint16_t collector_port, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence) {
    if (record_count == MAX_NETFLOW_PACKET) {
        packet.header.count = htons(record_count);
        sendNetFlowV5(collector_ip, collector_port, packet);
        record_count = 0;
        flow_sequence++;
        initNetFlowV5Packet(packet, flow_sequence);
    }
}

void populateNetFlowV5(const char *collector_ip, uint16_t collector_port, map<string, Flow> &flows, NetFlowV5Packet &packet, unsigned int &record_count, size_t &flow_sequence)
{
    // Fill records with flows from the map
    for (auto it = flows.begin(); it != flows.end();)
    {
        const Flow &flow = it -> second;
        populateNetFlowV5Packet(packet, record_count, flow);
        cout << "RECORD COUNT: " << record_count << endl;

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
    packet.header.sysUptime = htonl(reference_time);

    packet.header.unixSecs = htonl(reference_time / 1000);
    packet.header.unixNsecs = htonl((reference_time % 1000) * 1000000);
    packet.header.flowSequence = htonl(flow_sequence);
}

void moveActiveFlowsToBuffer() {
    for (auto it = activeFlows.begin(); it != activeFlows.end(); ) {
        flowsBuffer[it->first] = it->second;
        it = activeFlows.erase(it);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    string filename;
    string collIp;
    string collPort;

    reference_time = 0;
    activeTO = 60;
    inactiveTO = 60;

    //parse command line arguments and convert them into needed types
    parseArgs(argc, argv, filename, collIp, collPort, activeTO, inactiveTO);
    collector_ip = collIp.c_str();
    collector_port = static_cast<uint16_t>(stoi(collPort));
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
    size_t flow_sequence = 0;
    initNetFlowV5Packet(packet, flow_sequence);

    // process individual packets from pcap file in packet handler
    //agregate them into flows and populate neftlowV5 packet
    if(pcap_loop(handle, 0, packetHandler, (u_char*)&packet) < 0 ) {
        cerr << "Error reading packets from pcap file" << errbuf << endl;
        pcap_close(handle);
        return 1;
    }

    // Move reamining active flows to flowsBuffer
    moveActiveFlowsToBuffer();

    printFlows();

    // Populate final nfv5 packet and send it to collector
    if (flowsBuffer.size() > 0) {
        populateNetFlowV5(collector_ip, collector_port, flowsBuffer, packet, record_count, flow_sequence);
    }

    // Send any remaining records
    if (record_count > 0)
    {
        packet.header.count = htons(record_count);
        sendNetFlowV5(collector_ip, collector_port, packet);
        flow_sequence++;
    }

    //close pcap file
    pcap_close(handle);

    return 0;
}