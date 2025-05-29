#pragma once
#include "icmp.h"
#include "handshake.h"

struct encrypt_auth {
    uint32_t key_seed[4];
};

void encrypt_init(const char* password, const struct encrypt_auth* auth);

void encrypt_stream(const struct encrypt_auth* auth, const struct handshake_established* connection, struct icmp_message* msg);
void decrypt_stream(const struct encrypt_auth* auth, const struct handshake_established* connection, struct icmp_message* msg);

void encrypt_handshake(const struct encrypt_auth* auth, struct icmp_message* msg);
void decrypt_handshake(const struct encrypt_auth* auth, struct icmp_message* msg);
