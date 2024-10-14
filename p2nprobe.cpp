#include "p2nprobe.hpp"

void agregateFlows(Flow &flow) {
    
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
            //parse the TCP header
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

            Flow flow;
            flow.src_ip = ip_header->ip_src;
            flow.dst_ip = ip_header->ip_dst;
            flow.src_port = ntohs(tcp_header->th_sport);
            flow.dst_port = ntohs(tcp_header->th_dport);
            flow.protocol = ip_header->ip_p;
            flow.packet_count = 1;
            flow.byte_count = pkthdr->len;
            flow.flow_start = pkthdr->ts.tv_sec;
            flow.flow_end = pkthdr->ts.tv_sec;

            //agregate packets into flows
            agregateFlows(flow);
        }
    }
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

    //close pcap file
    pcap_close(handle);
    return 0;
}