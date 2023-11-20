/**
 * Author: Matej Nesuta
 * Login: xnesut00
 **/
#include "parser.h"
#include "utils.h"

#include <stdbool.h>

#include <netinet/if_ether.h>

extern struct pools pools;
extern struct source source;

// If DHCP overload (option 52) is present, this function is called to search
// for option 53 in sname/bootfile/both.
u_char* checkSnameAndBootfile(u_char* payload,
                              int option_type,
                              int overload_type) {
    u_char* type = NULL;
    switch (overload_type) {
        case 1:
            type = findOptionInOptions(payload + 44 + 64, option_type,
                                       payload + 236);
            break;
        case 2:
            type =
                findOptionInOptions(payload + 44, option_type, payload + 108);
            break;
        case 3:
            type =
                findOptionInOptions(payload + 44, option_type, payload + 108);
            if (type == NULL) {
                type = findOptionInOptions(payload + 44 + 64, option_type,
                                           payload + 236);
            }
            break;
    }
    return type;
}

// This function is used to look for specific option either in the option field,
// or in sname/bootfile.
u_char* findOptionInOptions(u_char* options,
                            int option_type,
                            u_char* payload_end) {
    while (*options != 255) {
        if (*options == option_type) {
            return options;
        } else if (options + 1 >= payload_end) {
            break;
        } else if (*options != 0) {
            options++;
            if ((options + *options + 1) < payload_end) {
                options += *options + 1;
            } else {
                break;
            }
        } else {
            options++;
        }
    }
    return NULL;
}

// This function compares 2 IPV4s in a network order.
void compareIPV4s(u_int32_t host, struct pool* pool, int set) {
    int64_t difference = (int64_t)(host - ((*pool).addr.s_addr));
    if (difference > 0 &&
        difference < (int64_t)(1l << (32 - (*pool).prefix)) - 1) {
        setBit((*pool).allocation.bits, difference, set);
    }
    return;
}

// This function was made using this tutorial:
// https://www.devdungeon.com/content/using-libpcap-c. It is called upon arrival
// of every packet.
void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
    args = NULL;
    struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;
    int ethernet_header_length = 14; /* Doesn't change */

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    const u_char* ip_header;
    const u_char* payload;
    int ip_header_length;
    int udp_header_length = 8;
    int payload_length;
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        return;
    }
    int total_headers_size =
        ethernet_header_length + ip_header_length + udp_header_length;
    payload_length = header->caplen - (ethernet_header_length +
                                       ip_header_length + udp_header_length);
    payload = packet + total_headers_size;

    if (payload_length > 241) {
        parseDHCP(payload, payload_length);
    }

    if (source.isInterface == true) {
        printOnline(pools);
    }
}

// This function is called when possible DHCP message was found.
void parseDHCP(const u_char* payload, int payload_size) {
    // DHCP cookie check.
    u_char* cookie = (u_char*)payload + 236;
    if (cookie[0] != 99 || cookie[1] != 130 || cookie[2] != 83 ||
        cookie[3] != 99) {
        return;
    }

    // Firstly, we want to search for option 53 in options.
    u_char* type =
        findOptionInOptions(cookie + 4, 53, (u_char*)payload + payload_size);
    u_char* overload = NULL;
    // If option 53 is not found, we search for option 52.
    if (type == NULL) {
        overload = findOptionInOptions(cookie + 4, 52,
                                       (u_char*)payload + payload_size);
    }

    // If option 52 was found, we continue the search in sname/bootfile.
    // Otherwise, the message is discarded.
    if (overload != NULL) {
        type = checkSnameAndBootfile((u_char*)payload, 53, overload[2]);
    }

    if (type != NULL) {
        // If ACK message is found, search through every network pool is done to
        // check if yiaddr belongs to any of these pools.
        if (type[2] == 5) {
            uint32_t* yiaddr = (uint32_t*)(payload + 16);
            for (size_t i = 0; i < pools.size; i++) {
                compareIPV4s(htonl(*yiaddr), pools.data + i, 1);
            }
        }
    }
}
