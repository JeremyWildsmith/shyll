#include "handshake_id.h"

#include <stdlib.h>

#include "util.h"

static unsigned short  KEY_HANDSHAKE = 0xB0B0;

static unsigned short COMMAND_ESTABLISH     = 0xAB00;
static unsigned short COMMAND_ESTABLISH_ACK = 0xAE00;

static unsigned short build_payload_handshaking(unsigned short echo_id, unsigned short echo_sequence) {
    return echo_id ^ echo_sequence ^ KEY_HANDSHAKE;
}

static int is_covert_handshaking(const struct icmp_message* msg) {
    if(msg->payload_sz < sizeof(unsigned short))
        return 0;

    const unsigned short data = *((unsigned short*)msg->payload_buffer);

    int is_handshaking = data ^ msg->sequence ^ msg->id == KEY_HANDSHAKE;

    return is_handshaking;
}

int build_establish_id(struct icmp_message* dest, unsigned short echo_id, unsigned char verify_step) {
    dest->sequence = random();
    dest->ttl = 64;
    dest->id = echo_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_handshaking(echo_id, dest->sequence);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    unsigned short message = COMMAND_ESTABLISH | verify_step;

    return pad_for_checksum(dest, message);
}

int build_verify_id(struct icmp_message* dest, unsigned short echo_id, unsigned char verify_step) {
    dest->sequence = random();
    dest->ttl = 64;
    dest->id = echo_id;
    dest->is_reply = 0;
    dest->sender_ip[0] = 0;
    dest->is_padded = 0;

    unsigned short data = build_payload_handshaking(echo_id, dest->sequence);

    dest->payload_sz = sizeof(unsigned short);
    *((unsigned short*)dest->payload_buffer) = data;

    unsigned short message = COMMAND_ESTABLISH_ACK | verify_step;
    return pad_for_checksum(dest, message);
}

int parse_handshake(const struct icmp_message* msg, const struct handshake_parse_callback* callback, void* userdata) {
    if (msg->is_reply)
        return 0;

    if(!is_covert_handshaking(msg))
        return 0;

    unsigned short command = msg->checksum & 0xFF00;

    process_handshake_message handler = NULL;

    if (command == COMMAND_ESTABLISH)
        handler = callback->establish;
    else
        handler = callback->verify;

    if (!handler)
        return 0;

    handler(userdata, msg->sender_ip, msg->id, msg->checksum & 0xFF);
    return 1;
}
