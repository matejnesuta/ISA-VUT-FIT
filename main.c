#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// sources
// https://www.devdungeon.com/content/using-libpcap-c
// https://linux.die.net/man/3/pcap_open_live
// https://www.tcpdump.org/manpages/pcap.3pcap.html
// https://man7.org/linux/man-pages/man3/inet_pton.3.html
// https://www.geeksforgeeks.org/bit-fields-c/
// https://stackoverflow.com/questions/22183561/how-to-compare-two-ip-address-in-c
// https://datatracker.ietf.org/doc/html/rfc2131
// https://datatracker.ietf.org/doc/html/rfc1533
// https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
// https://www.codementor.io/@hbendali/c-c-macro-bit-operations-ztrat0et6
// https://www.geeksforgeeks.org/count-set-bits-in-an-integer/

#define TIMEOUT 10000
#define FILTER_EXPRESSION "port 67 or port 68"

struct source {
    char* name;
    bool isInterface;
};

struct bitArray {
    char* bits;
    size_t size;  // Size of the bit array in bytes
};

struct pool {
    struct in_addr addr;
    unsigned short prefix;
    struct bitArray allocation;
};

struct pools {
    struct pool* data;
    size_t size;
};
// void print_packet_info(const u_char* packet, struct pcap_pkthdr
//     printf("Packet capture length: %d\n", packet_header.caplen);
//     printf("Packet total length %d\n", packet_header.len);
//     packet += 0;
// }

void errprint(char* err) {
    fprintf(stderr, "%s", err);
}

char* createBitArray(size_t size) {
    char* bits = NULL;
    if (size != 0) {
        bits = (char*)malloc(size * sizeof(char));
        if (bits == NULL) {
            errprint("malloc error\n");
            exit(6);
        }
        for (size_t i = 0; i < size; i++) {
            bits[i] = 0;
        }
    }
    return bits;
}

// https://stackoverflow.com/a/698108
uint32_t countBitsInByte(char n) {
    const unsigned char oneBits[] = {0, 1, 1, 2, 1, 2, 2, 3,
                                     1, 2, 2, 3, 2, 3, 3, 4};

    uint32_t result;

    result = oneBits[n & 0x0f];
    // printf("%u\n", result);
    n = n >> 4;
    result += oneBits[n & 0x0f];
    // printf("%u\n", result);
    return result;
}

uint32_t countTotalBits(struct bitArray arr) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < arr.size; i++) {
        count += countBitsInByte(arr.bits[i]);
    }
    return count;
}

u_char* findOptionInOptions(u_char* options, int option_type) {
    while (*options != 255) {
        if (*options == option_type) {
            return options;
        } else if (*options != 0) {
            options++;
            options += *options + 1;
        } else {
            options++;
        }
    }
    return NULL;
}

void setBit(char* bits, size_t index, int set) {
    size_t byteIndex = index / 8;
    size_t bitOffset = index % 8;
    // printf("index: %d\n", index);
    // printf("byteIndex: %d\n", byteIndex);
    // printf("offset: %d\n", bitOffset);
    if (set) {
        bits[byteIndex] |= (1 << bitOffset);
    } else {
        bits[byteIndex] &= ~(1 << bitOffset);
    }
}

// compare 2 IPV4s in network order
void compareIPV4s(u_int32_t host, struct pool* pool, int set) {
    int64_t difference = (int64_t)(host - ((*pool).addr.s_addr));
    if (difference > 0 &&
        difference < (int64_t)(1l << (32 - (*pool).prefix)) - 1) {
        setBit((*pool).allocation.bits, difference, set);
    }
}

u_char* checkSnameAndBootfile(u_char* options,
                              int option_type,
                              int overload_type) {
    u_char* type = NULL;
    switch (overload_type) {
        case 1:
            type = findOptionInOptions(options + 44 + 64, 53);
            break;
        case 2:
            type = findOptionInOptions(options + 44, 53);
            break;
        case 3:
            type = findOptionInOptions(options + 44, 53);
            if (type == NULL) {
                type = findOptionInOptions(options + 44 + 64, 53);
            }
            break;
    }
    return type;
}

void parseDHCP(const u_char* payload, int payload_size, struct pools* pools) {
    u_char* cookie = (u_char*)payload + 236;
    if (cookie[0] != 99 || cookie[1] != 130 || cookie[2] != 83 ||
        cookie[3] != 99) {
        return;
    }

    u_char* type = findOptionInOptions(cookie + 4, 53);
    u_char* overload = NULL;
    if (type == NULL) {
        overload = findOptionInOptions(cookie + 4, 52);
    }

    if (overload != NULL) {
        type = checkSnameAndBootfile((u_char*)payload, 53, overload[2]);
    }

    if (type != NULL) {
        if (type[2] == 5) {
            uint32_t* yiaddr = (uint32_t*)(payload + 16);
            for (size_t i = 0; i < (*pools).size; i++) {
                compareIPV4s(htonl(*yiaddr), (*pools).data + i, 1);
            }
        }
    }
}

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
    /* First, lets make sure we have an IP packet */
    struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;
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
    int ethernet_header_length = 14; /* Doesn't change */
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
        parseDHCP(payload, payload_length, (struct pools*)args);
    }

    return;
}

void helpAndExit() {
    errprint("Wrong args detected.\n");
    printf(
        "\n./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ "
        "<ip-prefix> [ ... ] ]\n"
        "-r <filename> - pcap file to be used\n"
        "-i <interface> - interface to listen on\n\n"

        "<ip-prefix> - subnet to generate a statistic upon\n\n"

        "For example:\n"
        "./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 "
        "172.16.32.0/24\n\n");
    exit(1);
}

void argparse(int argc,
              char* argv[],
              struct source* source,
              struct pool** pools,
              size_t* size) {
    if (argc < 4) {
        helpAndExit();
    } else if (!strcmp(argv[1], "-i")) {
        source->isInterface = true;
    } else if (!strcmp(argv[1], "-r")) {
        source->isInterface = false;
    } else {
        helpAndExit();
    }
    source->name = *(argv + 2);

    char* ipaddr = NULL;
    char* prefix = NULL;
    char* end = NULL;
    char* arg = NULL;
    unsigned short prefixInt = 33;

    *size = 0;
    struct pool* data = NULL;
    struct in_addr addr;
    for (int i = 3; i < argc; i++) {
        arg = argv[i];
        if (strchr(arg, '/') != strrchr(arg, '/')) {
            helpAndExit();
        }
        ipaddr = strtok(arg, "/");
        prefix = strtok(NULL, "/");
        end = strtok(NULL, "/");
        if (ipaddr == NULL || prefix == NULL || end != NULL) {
            helpAndExit();
        }
        prefixInt = strtol(prefix, &end, 10);
        if (inet_pton(AF_INET, ipaddr, &addr) <= 0 ||
            (end != NULL && end[0] != '\0') || prefixInt > 32) {
            helpAndExit();
        }
        data = realloc(data, (*size + 1) * sizeof(struct pool));
        if (data == NULL) {
            errprint("Failure related to memory allocation.");
            exit(5);
        }
        // printf("%u\n", ntohl(addr.s_addr));
        addr.s_addr = (htonl(addr.s_addr) >> 32 - prefixInt) << 32 - prefixInt;
        data[*size].addr = addr;
        data[*size].prefix = prefixInt;
        size_t hosts = 1ul << (32 - prefixInt);
        data[*size].allocation.size = hosts < 8 ? 1 : hosts / 8;
        data[*size].allocation.bits =
            createBitArray(data[*size].allocation.size);
        (*size)++;
    }
    *pools = data;
}

int main(int argc, char* argv[]) {
    const u_char* packet = NULL;
    struct pcap_pkthdr packet_header;
    pcap_t* handle = NULL;
    int packet_count_limit = 0;
    struct source source;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pools pools;
    struct pool* data = NULL;
    size_t size;
    pools.data = NULL;

    argparse(argc, argv, &source, &data, &size);

    pools.data = data;
    pools.size = size;

    if (source.isInterface == false) {
        pcap_t* pcap_open_offline(const char* fname, char* errbuf);
        handle = pcap_open_offline(source.name, error_buffer);
    } else {
        handle = pcap_open_live(source.name, BUFSIZ, packet_count_limit,
                                TIMEOUT, error_buffer);
    }

    if (handle == NULL) {
        errprint(error_buffer);
        exit(2);
    }

    struct bpf_program filter;
    char filter_exp[] = FILTER_EXPRESSION;

    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) ==
        -1) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
        exit(2);
    }

    pcap_loop(handle, 0, packet_handler, (u_char*)&pools);
    pcap_close(handle);

    if (source.isInterface == false) {
        printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");
        for (size_t i = 0; i < pools.size; i++) {
            pools.data[i].addr.s_addr = htonl(pools.data[i].addr.s_addr);
            printf("%s/%u ", inet_ntoa(pools.data[i].addr),
                   pools.data[i].prefix);
            size_t hosts = (1ul << (32 - pools.data[i].prefix)) - 2;
            printf("%u ", hosts);
            size_t allocation = countTotalBits(pools.data[i].allocation);
            printf("%u ", allocation);
            printf("%.2f%%", 100.0 * ((float)allocation / (float)hosts));
            printf("\n");
        }
    }
    return 0;
}