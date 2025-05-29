#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int is_valid_ipv4(const char* ip) {
    if (strlen(ip) >= INET_ADDRSTRLEN)
        return 0;

    struct sockaddr_in b;
    
    return inet_pton(AF_INET, ip, &b);
}

void yield_ns(long ns_delay) {
    static struct timespec idle_sleep = {
        .tv_sec = 0
    };

    idle_sleep.tv_nsec = ns_delay;

    nanosleep(&idle_sleep, NULL);
}

void yield_proc() {
    yield_ns(10000000);
}

long elapsed_clock(struct timespec* start, struct timespec* end) {
    return (end->tv_sec - start->tv_sec) * 1000000000 + end->tv_nsec - start->tv_nsec;
}

int compare_uint16(const void* _a, const void* _b) {
    const unsigned short* a = _a;
    const unsigned short* b = _b;

    return *a - *b;
}

int create_address(const char* address, struct sockaddr_in* out) {
    struct in_addr addr;

    if(!inet_aton(address, &addr)) {
        fprintf(stderr, "Unable to parse destination IP Address.\n");
        return 0;
    }

    memset(out, 0, sizeof(*out));

    out->sin_addr = addr;
    out->sin_family = AF_INET;
    out->sin_port = 0;

    return 1;
}