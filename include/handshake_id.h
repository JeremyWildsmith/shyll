#pragma once

#include "icmp.h"

typedef void (*process_handshake_message)(void* userdata, const char* remote_ip, const unsigned short recv_id, const unsigned char recv_step);

struct handshake_parse_callback {
    process_handshake_message verify;
    process_handshake_message establish;
};

int build_establish_id(struct icmp_message* dest, unsigned short echo_id, unsigned char verify_step);
int build_verify_id(struct icmp_message* dest, unsigned short echo_id, unsigned char verify_step);

int parse_handshake(const struct icmp_message* msg, const struct handshake_parse_callback* callback, void* userdata);