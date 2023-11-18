#include "utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

struct source source;
struct pools pools;

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
    n = n >> 4;
    result += oneBits[n & 0x0f];
    return result;
}

uint32_t countTotalBits(struct bitArray arr) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < arr.size; i++) {
        count += countBitsInByte(arr.bits[i]);
    }
    return count;
}

void argparse(int argc, char* argv[], struct pool** pools, size_t* size) {
    if (argc < 4) {
        helpAndExit();
    } else if (!strcmp(argv[1], "-i")) {
        source.isInterface = true;
    } else if (!strcmp(argv[1], "-r")) {
        source.isInterface = false;
    } else {
        helpAndExit();
    }
    source.name = *(argv + 2);

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
        data[*size].syslog_sent = false;
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

void closeAndExit(int exit_code) {
    if (source.isInterface == true) {
        endwin();
    }
    exit(exit_code);
}

void errprint(char* err) {
    fprintf(stderr, "%s", err);
}

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT) {
        closeAndExit(0);
    }
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

void notifySyslog(char* ip, int prefix) {
    syslog(LOG_NOTICE, "prefix %s/%d exceeded 50%% of allocations", ip, prefix);
    printf("prefix %s/%d exceeded 50%% of allocations\n", ip, prefix);
}

void setBit(char* bits, size_t index, int set) {
    size_t byteIndex = index / 8;
    size_t bitOffset = index % 8;
    if (set) {
        bits[byteIndex] |= (1 << bitOffset);
    } else {
        bits[byteIndex] &= ~(1 << bitOffset);
    }
}
