#include "p2nprobe.hpp"

int main (int argc, char *argv[]) 
{
    int n;
    char errbuf[PCAP_ERRBUF_SIZE];      // constants defined in pcap.h
    const u_char *packet;               // pointer to the captured packet
    struct pcap_pkthdr header;          // PCAP header (packet envelope created by a packet capturing tool)
    pcap_t *handle;                     // file handle

    if(argc != 2) 
    {
        cerr << "No filename" << endl;
    }

    //open pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if(handle == NULL)
    {
        cerr << "Can't open pcap input file" << endl;
        return 1;  
    }

    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        n++;

        // print the captured packet info: packet number, length and timestamp
        printf("Packet no. %d:\n",n);
        printf("\tPacket length = %d bytes, received at %s",header.len,ctime((const time_t*)&header.ts.tv_sec));  
    }


    //close the file and deallocate
    pcap_close(handle);
    return 0;
}