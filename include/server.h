#pragma once
#include "icmp_encrypt.h"

struct listener_arguments {
    int fork_connections;
    int heartbeat;
    int cnc_daemon;
    struct encrypt_auth auth;
    unsigned int knock_window_length;
};

int run_server(struct listener_arguments* arguments);
