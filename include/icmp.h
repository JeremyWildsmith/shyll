#pragma once
#include <netinet/in.h>

struct icmp_message {
    char sender_ip[INET_ADDRSTRLEN];
    unsigned short checksum;
    unsigned short sequence;
    unsigned short id;
    int is_reply;
    int is_padded;
    unsigned char ttl;
    char payload_buffer[65536];
    unsigned int payload_sz;
};

struct icmp_session_context;

typedef void (*icmp_session)(void* userdata, struct icmp_session_context* session);

typedef void (*process_icmp)(void* userdata, const char* sender_ip, const unsigned short sequence, const unsigned short id, const unsigned short checksum, const int is_reply, const unsigned char ttl, const char* payload_buffer, const unsigned int payload_buffer_sz);
typedef int (*poll_icmp)();

uint16_t icmp_compute_checksum_delta(const struct icmp_message* message, const unsigned short target_checksum);
unsigned short compute_checksum(const struct icmp_message* message);
unsigned int send_ping(const char* addr_name, const struct icmp_message* message);

int pad_for_checksum(struct icmp_message* message, const uint16_t target_checksum);
void truncate_padding_for_checksum(struct icmp_message* message);

void icmp_monitor(icmp_session session, void* userdata);
int icmp_poll(struct icmp_session_context* ctx, struct icmp_message* dest);