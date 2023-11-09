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

#define TIMEOUT 10000
#define FILTER_EXPRESSION "port 67 or port 68"

struct source {
    char* name;
    bool isInterface;
};

struct pool {
    struct in_addr addr;
    unsigned short mask;
};

struct pools {
    struct pool* data;
    size_t size;
};
// void print_packet_info(const u_char* packet, struct pcap_pkthdr
// packet_header) {
//     printf("Packet capture length: %d\n", packet_header.caplen);
//     printf("Packet total length %d\n", packet_header.len);
//     packet += 0;
// }

void errprint(char* err) {
    fprintf(stderr, "%s", err);
}

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
    /* First, lets make sure we have an IP packet */
    struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;
    // zde dodat 2. typ ethernetu
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
       not have the whole packet. */
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

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
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    // TODO: tunelovani
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        return;
    }

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size =
        ethernet_header_length + ip_header_length + udp_header_length;
    // printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen - (ethernet_header_length +
                                       ip_header_length + udp_header_length);
    // printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    // printf("Memory address where payload begins: %p\n\n", payload);

    if (payload_length > 0) {
        const u_char* temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            // printf("%02x", *temp_pointer);
            temp_pointer++;
        }
        // printf("\n\n");
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
        printf("interface: %s\n", argv[2]);
        source->isInterface = true;
    } else if (!strcmp(argv[1], "-r")) {
        printf("file: %s\n", argv[2]);
        source->isInterface = false;
    } else {
        helpAndExit();
    }
    source->name = *(argv + 2);

    char* ipaddr = NULL;
    char* prefix = NULL;
    char* end = NULL;
    char* arg = NULL;
    int mask = -1;

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
        printf("ip addr: %s\n", ipaddr);
        printf("prefix: %s\n", prefix);
        printf("end: %s\n", end);
        mask = strtol(prefix, &end, 10);
        if (inet_pton(AF_INET, ipaddr, &addr) <= 0 ||
            (end != NULL && end[0] != '\0') || mask < 0 || mask > 32) {
            helpAndExit();
        }
        data = realloc(data, (*size + 1) * sizeof(struct pool));
        if (data == NULL) {
            errprint("Failure related to memory allocation.");
            exit(5);
        }
        data[*size].addr = addr;
        data[*size].mask = mask;
        (*size)++;
        printf("%s\n", argv[i]);
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

    // printf("%d\n", pools.size);
    // printf("%d\n", pools.data[0].mask);
    // printf("%d\n", pools.data[1].mask);
    // printf("%d\n", pools.data[2].mask);

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

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}