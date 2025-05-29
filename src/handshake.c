#include "handshake.h"

#include <sched.h>

#include "stream.h"
#include "icmp.h"
#include "icmp_encrypt.h"
#include "handshake_id.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

static const unsigned long VERIFY_TIMEOUT_THRESHOLD = 3;

static const int VERIFY_COUNT = 11;

struct handshake_state {
    char remote_ip[INET_ADDRSTRLEN];
    unsigned short established_id;
    int verify_step;
    unsigned long last_verify_time;
    test_allow_id_allocation allow_id;

    const struct encrypt_auth* auth;
};

struct handshake_icmp_userdata {
    struct handshake_established* result;
    struct handshake_state* state;
    unsigned long timeout;
    int is_listening;
    int result_status;
};

static void send_id(const struct encrypt_auth* auth, const char* host, unsigned short echo_id, unsigned char verify_step) {
    struct icmp_message message;
    build_establish_id(&message, echo_id, verify_step);
    encrypt_handshake(auth, &message);
    send_ping(host, &message);
}

static void send_verify_id(const struct encrypt_auth* auth, const char* host, unsigned short echo_id, unsigned short verify_step) {
    struct icmp_message message;
    build_verify_id(&message, echo_id, verify_step);

    encrypt_handshake(auth, &message);
    send_ping(host, &message);
}

static void handshake_listener_recv_establish(void* _state, const char* remote_ip, const unsigned short recv_id, const unsigned char recv_step) {
    struct handshake_state* state = _state;

    int initial_contact = state->verify_step == 0;

    if (!initial_contact && strcmp(remote_ip, state->remote_ip) != 0) {
        if (strcmp(remote_ip, state->remote_ip) != 0)
            return;
    }

    if (state->allow_id && !state->allow_id(recv_id))
        return;

    if (initial_contact) {
        strncpy(state->remote_ip, remote_ip, sizeof(state->remote_ip));
        state->established_id = recv_id;
    } else if (state->established_id != recv_id)
        return;

    state->last_verify_time = time(NULL);
    state->verify_step = state->verify_step > recv_step ? recv_step : state->verify_step;
    state->verify_step += 2;

    send_verify_id(state->auth, state->remote_ip, recv_id, state->verify_step);
}

static void handshake_logic_listener(struct icmp_session_context* icmp, struct handshake_state* state) {
    struct icmp_message message;
    struct handshake_parse_callback callback = {
        .establish = handshake_listener_recv_establish,
        .verify = NULL
    };

    while (icmp_poll(icmp, &message)) {
        decrypt_handshake(state->auth, &message);
        parse_handshake(&message, &callback, state);
    }
}

static void handshake_client_recv_verify(void* _state, const char* remote_ip, const unsigned short recv_id, const unsigned char recv_step) {
    struct handshake_state* state = _state;

    if (strcmp(remote_ip, state->remote_ip) != 0)
        return;

    if (recv_id != state->established_id)
        return;

    state->verify_step = state->verify_step > recv_step ? recv_step : state->verify_step;
    state->verify_step++;

    state->last_verify_time = time(NULL);
}

static void handshake_logic_client(struct icmp_session_context* icmp, struct handshake_state* state) {
    if(state->verify_step == 0) {
        state->established_id = random();
    }

    struct icmp_message message;
    struct handshake_parse_callback callback = {
        .establish = NULL,
        .verify = handshake_client_recv_verify
    };

    while (icmp_poll(icmp, &message)) {
        decrypt_handshake(state->auth, &message);
        parse_handshake(&message, &callback, state);
    }

    int awaiting_ack = state->verify_step % 2;

    if(!awaiting_ack && state->verify_step <= VERIFY_COUNT) {
        state->last_verify_time = time(NULL);
        state->verify_step++;
        send_id(state->auth, state->remote_ip, state->established_id, state->verify_step);
    }
}

static int handshake_logic(struct icmp_session_context* icmp, struct handshake_state* state, int is_listener) {
    if(time(NULL) - state->last_verify_time > VERIFY_TIMEOUT_THRESHOLD) {
        state->verify_step = 0;
        state->last_verify_time = time(NULL);
    }

    if(is_listener)
        handshake_logic_listener(icmp, state);
    else
        handshake_logic_client(icmp, state);

    return state->verify_step > VERIFY_COUNT;
}

static void do_handshake(void* _ctx, struct icmp_session_context* icmp) {
    struct handshake_icmp_userdata* ctx = _ctx;

    unsigned long start_time = time(NULL);
    while (ctx->timeout == 0 || time(NULL) - start_time <= ctx->timeout) {
        if (handshake_logic(icmp, ctx->state, ctx->is_listening)) {
            ctx->result->established_id = ctx->state->established_id;
            strncpy(ctx->result->remote_ip, ctx->state->remote_ip, INET_ADDRSTRLEN);
            ctx->result_status = 1;
            return;
        }
        yield_proc();
    }

    ctx->result_status = 0;
}

static int handshake(struct handshake_established* result, struct handshake_state* state, unsigned long timeout, int is_listening) {
    struct handshake_icmp_userdata userdata = {
        .result = result,
        .result_status = 0,
        .timeout = timeout,
        .is_listening = is_listening,
        .state = state
    };

    icmp_monitor(do_handshake, &userdata);

    return userdata.result_status;
}

int handshake_connect(const struct encrypt_auth* auth, const char* remote_ip, unsigned long timeout, struct handshake_established* result) {
    struct handshake_state state = {
        .established_id = 0,
        .verify_step = 0,
        .last_verify_time = 0,
        .allow_id = 0,
        .auth = auth
    };

    strncpy(state.remote_ip, remote_ip, INET_ADDRSTRLEN);

    result->is_listener = 0;

    return handshake(result, &state, timeout, 0);
}

int handshake_listen(const struct encrypt_auth* auth, unsigned long timeout, test_allow_id_allocation allow_id, struct handshake_established* result) {
    struct handshake_state state = {
        .established_id = 0,
        .verify_step = 0,
        .last_verify_time = 0,
        .allow_id = allow_id,
        .auth = auth
    };

    state.remote_ip[0] = 0;

    result->is_listener = 1;

    return handshake(result, &state, timeout, 1);
}
