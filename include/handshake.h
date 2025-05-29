#pragma once
#include <netinet/in.h>

struct encrypt_auth;

struct handshake_established {
    char remote_ip[INET_ADDRSTRLEN];
    unsigned short established_id;
    int is_listener;
};

typedef int (*test_allow_id_allocation)(unsigned short id);

int handshake_listen(const struct encrypt_auth* auth, unsigned long timeout, test_allow_id_allocation allow_id, struct handshake_established* result);
int handshake_connect(const struct encrypt_auth* auth, const char* remote_ip, unsigned long timeout, struct handshake_established* result);