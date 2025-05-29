#pragma once
#include "icmp.h"

int is_valid_ipv4(const char* ip);
int pad_for_checksum(struct icmp_message* message, const uint16_t target_checksum);
void truncate_padding_for_checksum(struct icmp_message* message);
void yield_proc();
void yield_ns(long ns_delay);
long elapsed_clock(struct timespec* start, struct timespec* end);
int compare_uint16(const void* _a, const void* _b);
int create_address(const char* address, struct sockaddr_in* out);