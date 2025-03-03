# PCAP NetFlowV5 Exporter

This program is designed to process pcap files and extract NetFlow v5 data. It efficiently aggregates TCP flows, monitors timeouts, and sends the flow data to a designated collector. With support for command-line arguments, the program allows you to configure active and inactive timeouts.

## How to run
### Prerequisities
- g++
- libcap

### Compile

Run `make` in the root folder.

### Usage

`./p2nprobe <path to pcap file> [-a <active timeout>] [-i <inactive timeout>] <collector_ip:collector_port>`

- -a: active timeout in seconds
- -i: inactive timeout in seconds
- pcap file: PCAP file
- collector_ip: collector's IP address
- collector_port: collector's port

### Example usage
`./p2nprobe test.pcap -a 10 -i 3 127.0.0.1:2055`