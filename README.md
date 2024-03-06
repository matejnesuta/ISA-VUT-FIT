# ISA project 2023/2024
## DHCP monitoring tool for network prefix utilization
### Author: Matej Nesuta
### Login: xnesut00
### Date: 20. 11. 2023
### Points scored: 18/20

## Description
Simple program in C, which provides statistics about the utilizations of a DHCP pool. 
The program works as a console application when analyzing a network interface. 
When utilization of a prefix surpasses 50% the program should send a syslog message. 
The program also has an option to parse a .pcap file, instead of choosing a network interface. 
In this case, the results are printed on the standard output after the parsing is finished.

## Limitations
IPv4 addresses only:
The tool is designed to work exclusively with IPv4 addresses. Support for IPv6 or other address types is not included.

No tunneling or VLAN support:
Tunneling functionality is not supported in this tool. It operates solely within the constraints of IPv4 networking. Vlan tags are also not supported.

## Usage
For usage there is `helpAndExit()` function which prints help message. 

Example of usage with filename:
```
./dhcp-stats -r dhcp.pcapng 192.168.1.0/24 192.168.0.0/22
```
Output:
```
IP-Prefix Max-hosts Allocated addresses Utilization
192.168.1.0/24 254 0 0.00%
192.168.0.0/22 1022 1 0.10%
```

## List of files
- main.c - main file
- parser.c - file for parsing the DHCP message
- parser.h - header file for parser.c
- utils.c - file for miscellaneous functions
- utils.h - header file for utils.c
- Makefile - makefile for compilation
- README - readme file
- manual.pdf - manual for this project
- dhcp-stats.1 - man page for this project

