#pragma once

struct client_arguments {
    char* remote_ip;
    const char* password;
    int non_interactive;
    int heartbeat;
};

int run_client(struct client_arguments* arguments);
int do_knock(const char* remote, const char* password);