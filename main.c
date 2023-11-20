/**
 * Author: Matej Nesuta
 * Login: xnesut00
 **/
#include <ncurses.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "parser.h"
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

extern struct pools pools;
extern struct source source;
extern pcap_t* handle;

// Parts of this main function are from this tutorial:
// https://www.devdungeon.com/content/using-libpcap-c.
int main(int argc, char* argv[]) {
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    char error_buffer[PCAP_ERRBUF_SIZE];

    pools.data = NULL;

    argparse(argc, argv, &pools.data, &pools.size);

    if (source.isInterface == false) {
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

    if (pcap_compile(handle, &filter, FILTER_EXPRESSION, 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
        exit(2);
    }

    pcap_set_immediate_mode(handle, 1);

    pcap_loop(handle, 0, packet_handler, (u_char*)&pools);

    if (source.isInterface == false) {
        printOffline();
    } else {
        endwin();
    }
    closeAndExit();
    return 0;
}
