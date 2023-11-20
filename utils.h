/**
 * Author: Matej Nesuta
 * Login: xnesut00
 **/
#ifndef __UTILS_H__
#define __UTILS_H__
#include <ncurses.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct source {
    bool isInterface;
    char* name;
};

struct bitArray {
    char* bits;
    size_t size;  // Size of the bit array in bytes
};

struct pool {
    bool syslog_sent;
    struct bitArray allocation;
    struct in_addr addr;
    unsigned short prefix;
};

struct pools {
    struct pool* data;
    size_t size;
};

struct source;
struct pools;

char* createBitArray(size_t);
uint32_t countBitsInByte(char n);
uint32_t countTotalBits(struct bitArray);
void argparse(int, char*[], struct pool**, size_t*);
void closeAndExit();
void errprint(char*);
void freePool();
void handle_signal(int);
void helpAndExit();
void notifySyslog(char*, int);
void printOffline();
void printOnline();
void setBit(char*, size_t, int);
void validatePrefixAndIP(char*, struct in_addr*, unsigned short*);

#endif
