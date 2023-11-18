#include "parser.h"
#include "utils.h"

#include <stdbool.h>

#include <netinet/if_ether.h>

extern struct pools pools;
extern struct source source;

u_char* checkSnameAndBootfile(u_char* payload,
                              int option_type,
                              int overload_type) {
    u_char* type = NULL;
    switch (overload_type) {
        case 1:
            type = findOptionInOptions(payload + 44 + 64, 53, payload + 236);
            break;
        case 2:
            type = findOptionInOptions(payload + 44, 53, payload + 108);
            break;
        case 3:
            type = findOptionInOptions(payload + 44, 53, payload + 108);
            if (type == NULL) {
                type =
                    findOptionInOptions(payload + 44 + 64, 53, payload + 236);
            }
            break;
    }
    return type;
}

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

// compare 2 IPV4s in network order
void compareIPV4s(u_int32_t host, struct pool* pool, int set) {
    int64_t difference = (int64_t)(host - ((*pool).addr.s_addr));
    if (difference > 0 &&
        difference < (int64_t)(1l << (32 - (*pool).prefix)) - 1) {
        setBit((*pool).allocation.bits, difference, set);
    }
    return;
}

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
    /* First, lets make sure we have an IP packet */
    struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;
    int ethernet_header_length = 14; /* Doesn't change */

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may

    /* Pointers to start point of various headers */
    const u_char* ip_header;
    const u_char* payload;

    /* Header lengths in bytes */
    int ip_header_length;
    int udp_header_length = 8;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;

    // TODO: tunelovani
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        return;
    }

    /* Add up all the header sizes to find the payload offset */
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

void parseDHCP(const u_char* payload, int payload_size) {
    u_char* cookie = (u_char*)payload + 236;
    if (cookie[0] != 99 || cookie[1] != 130 || cookie[2] != 83 ||
        cookie[3] != 99) {
        return;
    }

    u_char* type =
        findOptionInOptions(cookie + 4, 53, (u_char*)payload + payload_size);
    u_char* overload = NULL;
    if (type == NULL) {
        overload = findOptionInOptions(cookie + 4, 52,
                                       (u_char*)payload + payload_size);
    }

    if (overload != NULL) {
        type = checkSnameAndBootfile((u_char*)payload, 53, overload[2]);
    }

    if (type != NULL) {
        if (type[2] == 5) {
            uint32_t* yiaddr = (uint32_t*)(payload + 16);
            for (size_t i = 0; i < pools.size; i++) {
                compareIPV4s(htonl(*yiaddr), pools.data + i, 1);
            }
        }
    }
}
