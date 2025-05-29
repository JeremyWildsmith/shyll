#include "icmp_encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <netinet/ip_icmp.h>

#include "icmp.h"
#include "handshake.h"

static const char* DEFAULT_PASSWORD = "default";
static const char TEA_PAYLOAD_PADDING = 'a';
static const int TEA_BLOCK_SIZE = sizeof(uint32_t) * 2;

void encrypt_init(const char* password, const struct encrypt_auth* auth) {
    if (strlen(password) == 0)
        password = DEFAULT_PASSWORD;

    unsigned char md5[16];

    MD5((const unsigned char*)password, strlen(password), md5);

    for (int i = 0; i < sizeof(auth->key_seed); i++) {
        unsigned char src = md5[i % sizeof(md5)];
        *(((unsigned char*)auth->key_seed) + i) = src;
    }
}

static void tea_encrypt_pair(uint32_t* block_a, uint32_t* block_b, const uint32_t key[4]) {
    //Just re-implemented algorithm from wikipedia...
    //https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
    uint32_t v0 = *block_a;
    uint32_t v1 = *block_b;
    uint32_t sum = 0;

    for (uint32_t i = 0; i < 32; i++) {
        sum += 0x9E3779B9;
        v0 += ((v1<<4) + key[0]) ^ (v1 + sum) ^ ((v1>>5) + key[1]);
        v1 += ((v0<<4) + key[2]) ^ (v0 + sum) ^ ((v0>>5) + key[3]);
    }

    *block_a=v0;
    *block_b=v1;
}

static void tea_decrypt_pair(uint32_t* block_a, uint32_t* block_b, const uint32_t key[4]) {
    //Just re-implemented algorithm from wikipedia...
    //https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
    uint32_t v0 = *block_a;
    uint32_t v1 = *block_b;
    uint32_t sum = 0xC6EF3720;

    for (uint32_t i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);

        sum -= 0x9E3779B9;
    }

    *block_a=v0;
    *block_b=v1;
}

static void tea_encrypt(const uint32_t key[4], struct icmp_message* message) {
    uint16_t checksum = compute_checksum(message);

    truncate_padding_for_checksum(message);

    //Can't control code or type
    const int usable_from_header = sizeof(struct icmphdr) - sizeof(uint16_t);

    while ((usable_from_header + message->payload_sz) % TEA_BLOCK_SIZE != 0) {
        if (message->payload_sz >= sizeof(message->payload_buffer)) {
            fprintf(stderr, "Unable to encrypt message. Too big! This shouldn't ever happen.\n");
            exit(1);
        }

        message->payload_buffer[message->payload_sz] = TEA_PAYLOAD_PADDING;
        message->payload_sz++;
    }

    uint16_t* const subblocks = (uint16_t* )message->payload_buffer;

    uint32_t a = message->sequence << 16 | message->id;
    uint32_t b = checksum << 16 | subblocks[0];

    tea_encrypt_pair(&a, &b, key);

    message->sequence = (a >> 16) & 0xFFFF;
    message->id = a & 0xFFFF;

    message->checksum = (b >> 16) & 0xFFFF;
    subblocks[0] = b & 0xFFFF;

    const unsigned int remaining_payload = message->payload_sz - sizeof(uint16_t);

    if (remaining_payload % (sizeof(uint32_t) * 2) != 0) {
        fprintf(stderr, "Error, subblocks should be multiple of 4.\n");
        exit(1);
    }

    unsigned int num_blocks = remaining_payload / sizeof(uint32_t);

    uint32_t* const blocks = (uint32_t*)&subblocks[1];

    for (int i = 0; i < num_blocks; i += 2 * sizeof(uint32_t)) {
        tea_encrypt_pair(&blocks[i], &blocks[i+1], key);
    }

    pad_for_checksum(message, message->checksum);
}

int tea_decrypt(const uint32_t key[4], struct icmp_message* message) {
    const int usable_from_header = sizeof(struct icmphdr) - sizeof(uint16_t);

    //For receving packets we don't know if they've been padded exactly. But we can infer it
    //since the alignment will be off if they have been

    if ((usable_from_header + message->payload_sz) % TEA_BLOCK_SIZE == 2) {
        message->is_padded = 1;
        truncate_padding_for_checksum(message);
    }

    if ((usable_from_header + message->payload_sz) % TEA_BLOCK_SIZE != 0) {
        //This isn't a valid message sent from a shyll. Likely just interference
        //from other ICMP echo commands on the system.
        return 0;
    }

    uint16_t* const subblocks = (uint16_t*)message->payload_buffer;

    uint32_t a = message->sequence << 16 | message->id;
    uint32_t b = message->checksum << 16 | subblocks[0];

    tea_decrypt_pair(&a, &b, key);

    message->sequence = (a >> 16) & 0xFFFF;
    message->id = a & 0xFFFF;
    message->checksum = (b >> 16) & 0xFFFF;
    subblocks[0] = b & 0xFFFF;

    const unsigned int remaining_payload = message->payload_sz - sizeof(uint16_t);

    if (remaining_payload % (sizeof(uint32_t) * 2) != 0) {
        fprintf(stderr, "Error, subblocks should be multiple of 4!\n");
    }

    unsigned int num_blocks = remaining_payload / sizeof(uint32_t);

    uint32_t* const blocks = (uint32_t*)&subblocks[1];

    for (int i = 0; i < num_blocks; i += 2 * sizeof(uint32_t)) {
        tea_decrypt_pair(&blocks[i], &blocks[i+1], key);
    }

    pad_for_checksum(message, message->checksum);

    return 1;
}

void encrypt_stream(const struct encrypt_auth* auth, const struct handshake_established* connection, struct icmp_message* msg) {
    const int rounds = 1 + connection->established_id % 8;

    for (int i = 0; i < rounds; i++)
        tea_encrypt(auth->key_seed, msg);
}

void decrypt_stream(const struct encrypt_auth* auth, const struct handshake_established* connection, struct icmp_message* msg) {
    const int rounds = 1 + connection->established_id % 8;

    for (int i = 0; i < rounds; i++)
        tea_decrypt(auth->key_seed, msg);
}

void encrypt_handshake(const struct encrypt_auth* auth, struct icmp_message* msg) {
    tea_encrypt(auth->key_seed, msg);
}

void decrypt_handshake(const struct encrypt_auth* auth, struct icmp_message* msg) {
    tea_decrypt(auth->key_seed, msg);
}