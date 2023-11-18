#ifndef __PARSER_H__
#define __PARSER_H__

#include <pcap.h>
#include <stdint.h>
#include "utils.h"

u_char* findOptionInOptions(u_char*, int, u_char*);
u_char* checkSnameAndBootfile(u_char*, int, int);
void compareIPV4s(u_int32_t, struct pool*, int);
void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void parseDHCP(const u_char*, int);

#endif
