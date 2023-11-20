/**
 * Author: Matej Nesuta
 * Login: xnesut00
 **/
#include "utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

// Global variable for the main struct, which contains all the necessary data.
struct pools pools;
// Global variable which indicates if a pcap file is being read or a network
// interface is used.
struct source source;
// Handle used by pcap to open specific pcap file or interface.
pcap_t* handle;

// Function, which is responsible for allocating storage for a single network
// pool. For example, /24 prefix will get 8 bytes upon allocation and each bit
// represents an address in that network pool.
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

// This was made using this anwser: https://stackoverflow.com/a/698108. This
// functions counts number of bits, which are set to 1, in a byte.
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

// This function is called upon argument parsing and it's purpose is to allocate
// a struct for single pool and also fill the member of that struct with
// relevant variables.
void allocatePool(struct pool** data,
                  size_t size,
                  struct in_addr addr,
                  unsigned short prefix) {
    *data = realloc(*data, (size + 1) * sizeof(struct pool));
    if (data == NULL) {
        errprint("Failure related to memory allocation.");
        exit(5);
    }
    (*data)[size].syslog_sent = false;
    addr.s_addr = (htonl(addr.s_addr) >> 32 - prefix) << 32 - prefix;
    (*data)[size].addr = addr;
    (*data)[size].prefix = prefix;
    size_t hosts = 1ul << (32 - prefix);
    (*data)[size].allocation.size = hosts < 8 ? 1 : hosts / 8;
    (*data)[size].allocation.bits =
        createBitArray((*data)[size].allocation.size);
}

// This function is responsible for checking the flags and arguments when
// running this program.
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

    *size = 0;
    struct pool* data = NULL;
    for (int i = 3; i < argc; i++) {
        unsigned short prefix;
        struct in_addr addr;
        validatePrefixAndIP(argv[i], &addr, &prefix);
        allocatePool(&data, *size, addr, prefix);
        (*size)++;
    }
    *pools = data;
}

// This function frees a struct associated with a network pool and also it's bit
// field.
void freePool() {
    for (size_t i = 0; i < pools.size; i++) {
        free(pools.data[i].allocation.bits);
    }
    free(pools.data);
}

// This is called before exiting to close the ncurses window (if opened) and to
// free the allocated memory.
void closeAndExit(int exit_code) {
    if (source.isInterface == true) {
        endwin();
    }
    freePool();
    pcap_close(handle);
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

// This is called when invalid args or flags are detected.
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

// This is called after a pcap file is parsed.
void printOffline() {
    printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (size_t i = 0; i < pools.size; i++) {
        pools.data[i].addr.s_addr = htonl(pools.data[i].addr.s_addr);
        printf("%s/%u ", inet_ntoa(pools.data[i].addr), pools.data[i].prefix);
        size_t hosts = (1ul << (32 - pools.data[i].prefix)) - 2;
        printf("%u ", hosts);
        size_t allocation = countTotalBits(pools.data[i].allocation);
        printf("%u ", allocation);
        printf("%.2f%%", 100.0 * ((float)allocation / (float)hosts));
        printf("\n");
    }
}

// This is called upon every new packet on the interface to refresh the screen.
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

// This code is taken from this quick tutorial on macros in C:
// https://www.codementor.io/@hbendali/c-c-macro-bit-operations-ztrat0et6.
void setBit(char* bits, size_t index, int set) {
    size_t byteIndex = index / 8;
    size_t bitOffset = index % 8;
    if (set) {
        bits[byteIndex] |= (1 << bitOffset);
    } else {
        bits[byteIndex] &= ~(1 << bitOffset);
    }
}

// Quick check if the prefix and IP are valid or not.
void validatePrefixAndIP(char* arg,
                         struct in_addr* addr,
                         unsigned short* prefix) {
    *prefix = 33;
    if (strchr(arg, '/') != strrchr(arg, '/')) {
        helpAndExit();
    }
    char* ipaddr = strtok(arg, "/");
    char* prefixStr = strtok(NULL, "/");
    char* end = strtok(NULL, "/");
    if (ipaddr == NULL || prefixStr == NULL || end != NULL) {
        helpAndExit();
    }
    *prefix = strtol(prefixStr, &end, 10);
    if (inet_pton(AF_INET, ipaddr, addr) <= 0 ||
        (end != NULL && end[0] != '\0') || *prefix > 32) {
        helpAndExit();
    }
}
