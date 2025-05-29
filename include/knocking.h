#pragma once
#include <stdatomic.h>
#include <stdio.h>

#include "icmp_encrypt.h"

#define KNOCK_SEQUENCE_LENGTH 8

enum KNOCK_COMMAND {
    knock_open,
    knock_timeout
};

struct knock_context {
    unsigned short knock_ports[KNOCK_SEQUENCE_LENGTH];
    unsigned long recv_knock_times[KNOCK_SEQUENCE_LENGTH];
    unsigned short recv_knock_sizes[KNOCK_SEQUENCE_LENGTH];

    pthread_t thread;

    atomic_ulong knock_time;

    FILE* tcpdump;
};

void knock_send(const struct encrypt_auth* auth, const char* remote);

int knock_startup(const struct encrypt_auth* auth, struct knock_context* ctx);

void knock_shutdown(const struct knock_context* ctx);

unsigned long knocking_last_open(const struct knock_context* ctx);