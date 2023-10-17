#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// sources
// https://www.devdungeon.com/content/using-libpcap-c
// https://linux.die.net/man/3/pcap_open_live
// https://www.tcpdump.org/manpages/pcap.3pcap.html

#define TIMEOUT 10000

struct source {
    char* name;
    bool isInterface;
};

void print_packet_info(const u_char* packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    packet += 0;
}

void errprint(char* err) {
    fprintf(stderr, "%s", err);
}

void my_packet_handler(u_char* args,
                       const struct pcap_pkthdr* header,
                       const u_char* packet) {
    /* Do something with the packet here.
       The print_packet_info() function shows in the
       previous example could be used here. */
    /* print_packet_info(packet, header); */
    print_packet_info(packet, *header);
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

void argparse(int argc, char* argv[], struct source* source) {
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

    for (int i = 3; i < argc; i++) {
        printf("%s\n", argv[i]);
    }
}

int main(int argc, char* argv[]) {
    const u_char* packet;
    struct pcap_pkthdr packet_header;
    pcap_t* handle;
    int packet_count_limit = 0;
    struct source source;
    char error_buffer[PCAP_ERRBUF_SIZE];
    argparse(argc, argv, &source);
    if (source.isInterface == false) {
        printf("PCAP files TBD\n");
        exit(0);
    } else {
        handle = pcap_open_live(source.name, BUFSIZ, packet_count_limit,
                                TIMEOUT, error_buffer);
        if (handle == NULL) {
            errprint(error_buffer);
            exit(2);
        }

        pcap_loop(handle, 0, my_packet_handler, NULL);
    }

    return 0;
}