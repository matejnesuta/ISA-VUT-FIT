#include <ncurses.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "utils.h"

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
// https://stackoverflow.com/questions/44084793/handle-signals-in-ncurses
// https://www.gnu.org/software/libc/manual/html_node/Syslog-Example.html

#define FILTER_EXPRESSION "port 68"

pcap_t* handle = NULL;
extern struct source source;
extern struct pools pools;

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
}

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

void printOnline() {
    mvprintw(0, 0, "IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (size_t i = 0; i < pools.size; i++) {
        struct in_addr addr;
        addr.s_addr = htonl(pools.data[i].addr.s_addr);
        size_t hosts = (1ul << (32 - pools.data[i].prefix)) - 2;
        size_t allocation = countTotalBits(pools.data[i].allocation);
        float percentage = 100.0 * ((float)allocation / (float)hosts);
        mvprintw(i + 1, 0, "%s/%u %u %u %.2f%%", inet_ntoa(addr),
                 pools.data[i].prefix, hosts, allocation, percentage);
        if (percentage > 50.00 && pools.data[i].syslog_sent == false) {
            pools.data[i].syslog_sent = true;
            notifySyslog(inet_ntoa(addr), pools.data[i].prefix);
        }
    }
    refresh();
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

int main(int argc, char* argv[]) {
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    const u_char* packet = NULL;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pool* data = NULL;
    size_t size;
    pools.data = NULL;

    argparse(argc, argv, &data, &size);

    pools.data = data;
    pools.size = size;

    if (source.isInterface == false) {
        pcap_t* pcap_open_offline(const char* fname, char* errbuf);
        handle = pcap_open_offline(source.name, error_buffer);
    } else {
        handle = pcap_open_live(source.name, BUFSIZ, 0, 100, error_buffer);
        initscr();
        printOnline(&pools);
        signal(SIGINT, handle_signal);
        signal(SIGQUIT, handle_signal);
        signal(SIGTERM, handle_signal);
    }

    if (handle == NULL) {
        errprint(error_buffer);
        closeAndExit(2);
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

    pcap_set_immediate_mode(handle, 1);

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
    } else {
        endwin();
    }
    return 0;
}