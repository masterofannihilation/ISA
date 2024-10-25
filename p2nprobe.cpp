/**
 * @author Boris Hatala xhatal02
 * @file p2nprobe.cpp
 * @date 
 * @todo - timeouts :   determine flow where each packet belongs 
 *                      update flow
 *                      check active and inactive timeouts
 *                      either export the flow or up
 *                      
 */

#include "p2nprobe.hpp"

std::chrono::milliseconds getSystemUptime() {
    std::chrono::milliseconds uptime(0u);
    double uptime_seconds;
    if (std::ifstream("/proc/uptime", std::ios::in) >> uptime_seconds) {
        uptime = std::chrono::milliseconds(
            static_cast<unsigned long long>(uptime_seconds * 1000.0)
        );
    }
    return uptime;
}

void parseArgs(int argc, char *argv[], string &filename, string &collector_ip, string &collector_port, int &activeTO, int& inactiveTO) {
    int opt;
    //default values
    activeTO = 60;
    inactiveTO = 60;

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

void initNetFlowV5Packet(NetFlowV5Packet &packet, size_t flow_sequence) {
    //zero out whole header of packet and set header
    memset(&packet, 0, sizeof(packet));
    packet.header.version = htons(5);
    packet.header.sysUptime = htonl(getSystemUptime().count());

    packet.header.unixSecs = htonl(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    packet.header.unixNsecs = htonl(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() % 1000 * 1000000);

    packet.header.flowSequence = htonl(flow_sequence);
}

void sendNetFlowV5(const char* collector_ip, uint16_t collector_port, const NetFlowV5Packet &packet){
    //Create a UDP socket
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( udpSocket< 0){
        cerr << "Failed to create socket" << endl;
    }

    struct sockaddr_in collAddr;
    memset(&collAddr, 0, sizeof(collAddr)); // Zero out the entire structure
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

int main (int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    string filename;
    string collIp;
    string collPort;
    int activeTO;
    int inactiveTO;

    //parse command line arguments
    parseArgs(argc, argv, filename, collIp, collPort, activeTO, inactiveTO);

    //convert them into needed types
    const char* collector_ip = collIp.c_str();
    uint16_t collector_port = static_cast<uint16_t>(stoi(collPort));
    const char* pcap_filename = filename.c_str();   

    //open pcap file
    handle = pcap_open_offline(pcap_filename, errbuf);
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

    printf("Number of flows agregated: %ld\n", flows.size());

    //initialize NetFlowV5 packet
    NetFlowV5Packet packet;
    size_t flow_sequence = 0;    
    size_t record_count = 0;

    //fill records with flows
    for(const auto &entry : flows) {
        const Flow &flow = entry.second;

        NetFlowV5Record &record = packet.records[record_count];
        record.srcAddr = flow.src_ip.s_addr;
        record.dstAddr = flow.dst_ip.s_addr;
        record.packets = htonl(flow.packet_count);
        record.bytes = htonl(flow.byte_count);
        record.srcPort = htons(flow.src_port);
        record.dstPort = htons(flow.dst_port);
        record.protocol = flow.protocol;
        record.first = htonl(flow.flow_start);
        record.last = htonl(flow.flow_end);

        record_count++;
        if(record_count == MAX_NETFLOW_PACKET){
            initNetFlowV5Packet(packet, flow_sequence);
            packet.header.count = htons(record_count);
            sendNetFlowV5(collector_ip, collector_port, packet);
            record_count = 0;
            flow_sequence++;                        
            initNetFlowV5Packet(packet, flow_sequence);
        }
    }

    // Send any remaining records
    if (record_count > 0) {
        initNetFlowV5Packet(packet, flow_sequence);
        packet.header.count = htons(record_count);
        sendNetFlowV5(collector_ip, collector_port, packet);
        flow_sequence++;
    }

    // printFlows();

    //close pcap file
    pcap_close(handle);

    return 0;
}