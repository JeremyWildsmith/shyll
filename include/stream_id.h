#pragma once

#include "icmp.h"
#include "handshake.h"

#define STREAM_COMMAND_SIGINT 1

typedef void (*process_stream_acknowledge)(void* userdata, unsigned short sequence);
typedef void (*process_stream_data)(void* userdata, const char* data, unsigned short sz, unsigned short sequence, unsigned char is_command);
typedef void (*process_stream_simple)(void* userdata);

struct parse_stream_callback {
    process_stream_simple keepalive;
    process_stream_simple keepalive_ack;
    process_stream_simple eof;
    process_stream_data data;
    process_stream_acknowledge data_ack;
};

int build_acknowledge_range(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence_a, unsigned short sequence_b, int is_listener);
int build_acknowledge_pair(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence_a, unsigned short sequence_b, int is_listener);
int build_acknowledge_single(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence, int is_listener);

int build_keepalive(struct icmp_message* dest, unsigned short stream_id, int is_ack, int is_listener);
int build_eof(struct icmp_message* dest, unsigned short stream_id, int is_listener);
int build_data(struct icmp_message* dest, unsigned short stream_id, unsigned short sequence, const unsigned char* data, unsigned short data_sz, int is_listener);
int build_command(struct icmp_message* dest, unsigned short stream_id, unsigned short sequence, const unsigned char* data, unsigned short data_sz, int is_listener);

int parse_stream(const struct handshake_established* connection, const struct icmp_message* msg, const struct parse_stream_callback* callback, void* userdata);