#include "p2nprobe.hpp"

void printFlows() {
    std::cout << "Current Flows:\n";
    for (const auto &entry : flows) {
        const Flow &flow = entry.second;
        std::cout << "Flow Key: " << entry.first << "\n";
        std::cout << "Source IP: " << inet_ntoa(flow.src_ip) << ":" << flow.src_port << "\n";
        std::cout << "Destination IP: " << inet_ntoa(flow.dst_ip) << ":" << flow.dst_port << "\n";
        std::cout << "Protocol: " << (flow.protocol == IPPROTO_TCP ? "TCP" : "Unknown") << "\n";
        std::cout << "Packet Count: " << flow.packet_count << "\n";
        std::cout << "Byte Count: " << flow.byte_count << "\n";
        std::cout << "Flow Start Time: " << flow.flow_start << "\n";
        std::cout << "Flow End Time: " << flow.flow_end << "\n";
        std::cout << "--------------------------------------\n";
    }
}

string createFlowKey(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port) {
    uint32_t src_ipINT = src_ip.s_addr;
    uint32_t dst_ipINT = dst_ip.s_addr;

    if (src_ipINT < dst_ipINT || (src_ipINT == dst_ipINT && src_port < dst_port))
        return string(inet_ntoa(src_ip)) + ":" + std::to_string(src_port) + "," + string(inet_ntoa(dst_ip)) + ":" + to_string(dst_port);
    else
        return string(inet_ntoa(dst_ip)) + ":" + std::to_string(dst_port) + "," + string(inet_ntoa(src_ip)) + ":" + to_string(src_port);
    
}

void agregateFlows(const struct ip *ip_header, const struct tcphdr *tcp_header, const struct pcap_pkthdr *pkthdr) {
    // Generate a flow key using the IP addresses and ports
    string key = createFlowKey(ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    // Check if the flow already exists
    if (flows.find(key) != flows.end()) {
        // Update the existing flow
        flows[key].packet_count++;
        flows[key].byte_count += pkthdr->len;
        flows[key].flow_end = pkthdr->ts.tv_sec;
    } else {
        // Create a new flow
        Flow newFlow;
        newFlow.src_ip = ip_header->ip_src;
        newFlow.dst_ip = ip_header->ip_dst;
        newFlow.src_port = ntohs(tcp_header->th_sport);
        newFlow.dst_port = ntohs(tcp_header->th_dport);
        newFlow.protocol = ip_header->ip_p;
        newFlow.packet_count = 1;
        newFlow.byte_count = pkthdr->len;
        newFlow.flow_start = pkthdr->ts.tv_sec;
        newFlow.flow_end = pkthdr->ts.tv_sec;

        // Add the new flow to the flows table
        flows[key] = newFlow;
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
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
            agregateFlows(ip_header, tcp_header, pkthdr);

            //check for RESET or FIN flags
            bool isFIN = tcp_header->th_flags & TH_FIN;
            bool isRST = tcp_header->th_flags & TH_RST;

            //send flow if FIN or RST packet detected
            if(isFIN || isRST) {
                //lefofneofpoefbeob 
            }
        }
    }
}

void sendNetFlowV5(const char* collector_ip, uint16_t collector_port, const std::vector<NetFlowV5Record>& records){
    //Create a UDP socket
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( udpSocket< 0){
        cerr << "Failed to create socket" << endl;
    }

    struct sockaddr_in collAddr;
    memset(&collAddr, 0, sizeof(collAddr)); // Zero out the entire structure
    collAddr.sin_family = AF_INET;
    collAddr.sin_port = htons(COLL_PORT);

    // Prepare NetFlow v5 packet
    NetFlowV5Header header;
    memset(&header, 0, sizeof(header));
    header.version = htons(5);
    header.count = htons(records.size());
    header.sysUptime = htonl(123456); // Example uptime
    header.unixSecs = htonl(time(NULL));
    header.unixNsecs = htonl(0);
    header.flowSequence = htonl(1); // Example sequence number

    /// Serialize header and records into buffer
    uint8_t buffer[NETFLOW_V5_HEADER_SIZE + NETFLOW_V5_MAX_RECORDS * NETFLOW_V5_RECORD_SIZE];
    memcpy(buffer, &header, NETFLOW_V5_HEADER_SIZE);
    for (size_t i = 0; i < records.size(); ++i) {
        memcpy(buffer + NETFLOW_V5_HEADER_SIZE + i * NETFLOW_V5_RECORD_SIZE, &records[i], NETFLOW_V5_RECORD_SIZE);
    }

    // Send packet to collector
    if (sendto(udpSocket, buffer, NETFLOW_V5_HEADER_SIZE + records.size() * NETFLOW_V5_RECORD_SIZE, 0,
               (const struct sockaddr*)&collAddr, sizeof(collAddr)) < 0) {
        perror("sendto failed");
    }

    close(udpSocket);
}

int main (int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];      // constants defined in pcap.h
    pcap_t *handle;                     // file handle

    if(argc != 2) {
        cerr << "No filename" << endl;
    }

    //open pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if(handle == NULL){
        cerr << "Error opening pcap file" << errbuf << endl;
        return 1;  
    }

    // process packets from pcap file
    if(pcap_loop(handle, 0, packetHandler, NULL) < 0 ) {
        cerr << "Error reading packets from pcap file" << errbuf << endl;
        pcap_close(handle);
        return 1;
    }

    const char* collector_ip = "127.0.0.1";
    uint16_t collector_port = 2055;

    std::vector<NetFlowV5Record> records;
    // Populate records with your flow data
    // Example:
    NetFlowV5Record record;
    memset(&record, 0, sizeof(record));
    record.srcAddr = inet_addr("147.229.197.85");
    record.dstAddr = inet_addr("157.240.30.63");
    record.packets = htonl(10);
    record.bytes = htonl(1000);
    records.push_back(record);

    sendNetFlowV5(collector_ip, collector_port, records);

    // printFlows();

    //close pcap file
    pcap_close(handle);
    return 0;
}