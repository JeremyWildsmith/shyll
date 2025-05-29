#include "stream_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

static unsigned short  KEY_DATA = 0xBAB0;
static unsigned short  KEY_COMMAND = 0xAAB0;

#define KEY_ACK_SINGLE 0xBBB0
#define  KEY_ACK_PAIR 0xBBC0
#define  KEY_ACK_RANGE 0xBBD0

static unsigned short  KEY_MASK = 0xFFFC;
static unsigned short  KEY_KEEPALIVE = 0xCCC0;
static unsigned short  KEY_EOF = 0xDDD0;

static int parse_covert_ack(const struct icmp_message* msg, unsigned char is_from_listener, unsigned short* ack_key) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;
    
    const unsigned short data = *((unsigned short*)msg->payload_buffer);

    const unsigned short result = (data ^ msg->sequence ^ msg->id);

    const unsigned short key_code = (result & KEY_MASK);

    if(key_code != KEY_ACK_SINGLE && key_code != KEY_ACK_PAIR && key_code != KEY_ACK_RANGE)
        return 0;

    *ack_key = key_code;

    int msg_from_listener = data & 2 ? 1 : 0;

    if (msg_from_listener && ! is_from_listener)
        return 0;

    return 1;
}

static int parse_covert_data(const struct icmp_message* msg, unsigned short* sz, unsigned char is_from_listener) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;

    const unsigned short original_data = *(unsigned short*)msg->payload_buffer;

    const unsigned short result = (original_data ^ msg->sequence ^ msg->id);

    if((result & KEY_MASK) != KEY_DATA)
        return 0;

    *sz = 1 + original_data % 2;

    int msg_from_listener = original_data & 2 ? 1 : 0;

    if (msg_from_listener && ! is_from_listener)
        return 0;

    return 1;
}

static int parse_covert_command(const struct icmp_message* msg, unsigned short* sz, unsigned char is_from_listener) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;

    const unsigned short original_data = *(unsigned short*)msg->payload_buffer;

    const unsigned short result = (original_data ^ msg->sequence ^ msg->id);

    if((result & KEY_MASK) != KEY_COMMAND)
        return 0;

    *sz = 1 + original_data % 2;

    int msg_from_listener = original_data & 2 ? 1 : 0;

    if (msg_from_listener && ! is_from_listener)
        return 0;

    return 1;
}

static int parse_covert_keepalive(const struct icmp_message* msg, unsigned char* is_ack, unsigned char is_from_listener) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;

    const unsigned short data = *((unsigned short*)msg->payload_buffer);

    int is_keepalive = ((data ^ msg->sequence ^ msg->id) & KEY_MASK) == KEY_KEEPALIVE;

    int msg_from_listener = data & 2 ? 1 : 0;

    if (msg_from_listener && ! is_from_listener)
        return 0;

    *is_ack = data & 1;

    return is_keepalive;
}

static int parse_eof(const struct icmp_message* msg, unsigned char is_from_listener) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;

    const unsigned short data = *((unsigned short*)msg->payload_buffer);

    int is_eof = ((data ^ msg->sequence ^ msg->id) & KEY_MASK) == KEY_EOF;

    if (!is_eof)
        return 0;

    int msg_from_listener = data & 2 ? 1 : 0;

    if (msg_from_listener && !is_from_listener)
        return 0;

    return is_eof;
}

static unsigned short build_payload_data(unsigned short echo_id, unsigned short echo_sequence, unsigned short sz, unsigned char is_from_listener) {
    unsigned short payload = (echo_id ^ echo_sequence ^ KEY_DATA) & (KEY_MASK);

    if(sz > 1)
        payload += 1;

    if (is_from_listener)
        payload += 2;

    return payload;
}

static unsigned short build_payload_command(unsigned short echo_id, unsigned short echo_sequence, unsigned short sz, unsigned char is_from_listener) {
    unsigned short payload = (echo_id ^ echo_sequence ^ KEY_COMMAND) & (KEY_MASK);

    if(sz > 1)
        payload += 1;

    if (is_from_listener)
        payload += 2;

    return payload;
}

static unsigned short build_payload_covert_ack(unsigned short echo_id, unsigned short echo_sequence, unsigned short ack_key, unsigned char is_from_listener) {
    unsigned short payload = (echo_id ^ echo_sequence ^ ack_key) & KEY_MASK;

    if (is_from_listener) {
        payload += 2;
    }

    return payload;
}

static unsigned short build_payload_keepalive(unsigned short echo_id, unsigned short echo_sequence, unsigned char is_ack, unsigned char is_from_listener) {
    unsigned short payload = (echo_id ^ echo_sequence ^ KEY_KEEPALIVE) & KEY_MASK;

    if (is_from_listener) {
        payload += 2;
    }

    if (is_ack) {
        payload += 1;
    }

    return payload;
}

static unsigned short build_payload_eof(unsigned short echo_id, unsigned short echo_sequence, unsigned char is_from_listener) {
    unsigned short payload = (echo_id ^ echo_sequence ^ KEY_EOF) & KEY_MASK;

    if (is_from_listener) {
        payload += 2;
    }

    return payload;
}

int build_acknowledge_single(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence, int is_listener) {
    dest->sequence = sequence;
    dest->ttl = 64;
    dest->id = echo_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_covert_ack(echo_id, sequence, KEY_ACK_SINGLE, is_listener);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    return 1;
}

int build_acknowledge_pair(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence_a, unsigned short sequence_b, int is_listener) {
    dest->sequence = sequence_a;
    dest->ttl = 64;
    dest->id = echo_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_covert_ack(echo_id, sequence_a, KEY_ACK_PAIR, is_listener);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    pad_for_checksum(dest, sequence_b);

    return 1;
}

int build_acknowledge_range(struct icmp_message* dest, unsigned short echo_id, unsigned short sequence_a, unsigned short sequence_b, int is_listener) {
    dest->sequence = sequence_a;
    dest->ttl = 64;
    dest->id = echo_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_covert_ack(echo_id, sequence_a, KEY_ACK_RANGE, is_listener);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    pad_for_checksum(dest, sequence_b);

    return 1;
}

int build_keepalive(struct icmp_message* dest, unsigned short stream_id, int is_ack, int is_listener) {
    dest->sequence = random();
    dest->ttl = 64;
    dest->id = stream_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_keepalive(stream_id, dest->sequence, is_ack, is_listener);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    return 1;
}

int build_eof(struct icmp_message* dest, unsigned short stream_id, int is_listener) {
    dest->sequence = random();
    dest->ttl = 64;
    dest->id = stream_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_eof(stream_id, dest->sequence, is_listener);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    return 1;
}

int build_data(struct icmp_message* dest, unsigned short stream_id, unsigned short sequence, const unsigned char* data, unsigned short data_sz, int is_listener) {
    if (data_sz == 0 || data_sz > 2) {
        fprintf(stderr, "Invalid data size argument. Assertion fails.\n");
        exit(0);
    }

    dest->sequence = sequence;
    dest->ttl = 64;
    dest->id = stream_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short payload = build_payload_data(stream_id, sequence, data_sz, is_listener);
    unsigned short checksum_data = *data;

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = payload;

    if (data_sz > 1)
        checksum_data |= data[1] << 8;

    pad_for_checksum(dest, checksum_data);
    return 1;
}

int build_command(struct icmp_message* dest, unsigned short stream_id, unsigned short sequence, const unsigned char* data, unsigned short data_sz, int is_listener) {
    if (data_sz == 0 || data_sz > 2) {
        fprintf(stderr, "Invalid data size argument. Assertion fails.\n");
        exit(0);
    }

    dest->sequence = sequence;
    dest->ttl = 64;
    dest->id = stream_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short payload = build_payload_command(stream_id, sequence, data_sz, is_listener);
    unsigned short checksum_data = *data;

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = payload;

    if (data_sz > 1)
        checksum_data |= data[1] << 8;

    pad_for_checksum(dest, checksum_data);
    return 1;
}

int parse_stream(const struct handshake_established* connection, const struct icmp_message* msg, const struct parse_stream_callback* callback, void* userdata) {
    if (msg->is_reply || msg->id != connection->established_id)
        return 0;

    if (strncmp(msg->sender_ip, connection->remote_ip, sizeof(msg->sender_ip)) != 0)
        return 0;

    unsigned short recv_data_sz;
    unsigned short ack_code;
    unsigned char is_keepalive_ack;

    if (parse_covert_ack(msg, !connection->is_listener, &ack_code)) {

        if (callback->data_ack) {
            switch (ack_code) {
                case KEY_ACK_SINGLE:
                    callback->data_ack(userdata, msg->sequence);
                    break;
                case KEY_ACK_PAIR:
                    callback->data_ack(userdata, msg->sequence);
                    callback->data_ack(userdata, msg->checksum);
                    break;
                case KEY_ACK_RANGE: {
                    for (int i = msg->sequence; i <= msg->checksum; i++)
                        callback->data_ack(userdata, i);

                    break;
                }
                default:
                    fprintf(stderr, "ERROR, Invalid ack code specified. Ignoring ack command.\n");
            }
        }

        return 1;
    }

    if (parse_covert_command(msg, &recv_data_sz, !connection->is_listener))
    {
        if (callback->data)
            callback->data(userdata, (const char*)&msg->checksum, recv_data_sz, msg->sequence, 1);

        return 1;
    }

    if (parse_covert_data(msg, &recv_data_sz, !connection->is_listener)) {
        if (callback->data)
            callback->data(userdata, (const char*)&msg->checksum, recv_data_sz, msg->sequence, 0);

        return 1;
    }

    if (parse_covert_keepalive(msg, &is_keepalive_ack, !connection->is_listener)) {
        if (is_keepalive_ack) {
            if (callback->keepalive_ack)
                callback->keepalive_ack(userdata);
        } else {
            if (callback->keepalive)
                callback->keepalive(userdata);
        }

        return 1;
    }

    if (parse_eof(msg, !connection->is_listener)) {
        if (callback->eof)
            callback->eof(userdata);

        return 1;
    }

    return 0;
}
