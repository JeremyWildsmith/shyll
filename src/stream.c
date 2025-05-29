#include "stream.h"

#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include <time.h>
#include <sys/queue.h>

#include "icmp.h"
#include "stream_id.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/param.h>

#include "icmp_encrypt.h"
#include "util.h"

#define DATA_CHUNK_SZ 2
#define WINDOW_SIZE 50

//These are tuned for reasonable performance. For simplicity no congestion control...
static const unsigned int SEND_TIMEOUT_NS = 60000000;

static const unsigned int STREAM_DEAD_THRESHOLD = 8;
static const unsigned int STREAM_KEEPALIVE_THRESHOLD = 4;
static const unsigned int KEEPALIVE_TRANSIT_INTERVAL = 1;
static const unsigned int MAX_SEND_KEEPALIVE = (STREAM_DEAD_THRESHOLD - STREAM_KEEPALIVE_THRESHOLD) / KEEPALIVE_TRANSIT_INTERVAL + 1;

//How many packets do we send per second. Aim for 2kbs at 1.0 of send window.
static const long TARGET_BYTE_RATE = 2096;
static const unsigned long DEFAULT_FLOW_INTERVAL_NS = 1000000000 / (TARGET_BYTE_RATE / 2);
static const unsigned int MAX_SEND_PER_INTERVAL = 200;
static const unsigned long MAX_INTERVAL_CARRYOVER = MAX_SEND_PER_INTERVAL * DEFAULT_FLOW_INTERVAL_NS;

struct stream_icmp_userdata {
    const struct handshake_established* established;
    const struct encrypt_auth* auth;
    stream_session session;
    int disable_heartbeat;
    void* userdata;
};

typedef struct datanode
{
    char data[DATA_CHUNK_SZ];
    unsigned int data_sz;
    unsigned char is_command;
    TAILQ_ENTRY(datanode) nodes;
} datanode_t;

typedef TAILQ_HEAD(datahead_s, datanode) datahead_t;

struct stream_session_context {
    datahead_t* send_head;
    datahead_t* recv_head;
    datahead_t* recv_cmd_head;
    pthread_mutex_t* io_mutex;
    pthread_cond_t* io_cond;
    atomic_bool heartbeat_alive;
    atomic_bool closed;
    atomic_bool data_to_read;
    atomic_bool command_to_read;
    atomic_bool pending_read;
    atomic_bool pending_write;
};

struct window_entry {
    char data[DATA_CHUNK_SZ];
    unsigned char data_sz;
    unsigned char is_command;
    char occupied;
    unsigned int index;
    unsigned long elapsed_since_sent;
};

struct stream_flow_state {
    struct window_entry send_window[WINDOW_SIZE];
    struct window_entry recv_window[WINDOW_SIZE];
    unsigned short recv_window_ack[WINDOW_SIZE];
    unsigned short recv_window_ack_len;

    unsigned short recv_next_writein;
    unsigned short send_next_writeout;

    unsigned long last_time_acked;
    int sent_keep_alive;
    int eof;

    unsigned long last_interval_carryover;
};

struct stream_daemon_ctx {
    struct stream_session_context* session_ctx;
    struct icmp_session_context* icmp;
    const struct handshake_established* connection;
    int disable_heartbeat;
    const struct encrypt_auth* auth;
};

struct stream_parse_userdata {
    const struct handshake_established* connection;
    struct stream_flow_state* flow;
    const struct encrypt_auth* auth;
};


struct window_entry* find_free_entry(struct window_entry* src) {
    for (unsigned int i = 0; i < WINDOW_SIZE; i++) {
        if (!src[i].occupied)
            return &src[i];
    }

    return NULL;
}

static void mark_acknowledge(struct stream_flow_state* flow, unsigned short sequence) {
    if (flow->recv_window_ack_len >= sizeof(flow->recv_window_ack) / sizeof(unsigned short))
        return;

    flow->recv_window_ack[flow->recv_window_ack_len++] = sequence;
}

static struct window_entry* find_existing_for_sequence(struct window_entry* src, unsigned short sequence) {
    for (unsigned int i = 0; i < WINDOW_SIZE; i++) {
        if (src[i].occupied && src[i].index == sequence)
            return &src[i];
    }

    return NULL;
}

static void send_keepalive(const struct encrypt_auth* auth, const struct handshake_established* connection, int is_ack) {
    struct icmp_message msg;

    build_keepalive(&msg, connection->established_id, is_ack, connection->is_listener);
    encrypt_stream(auth, connection, &msg);

    send_ping(connection->remote_ip, &msg);
}

static void send_eof(const struct encrypt_auth* auth, const struct handshake_established* connection) {
    struct icmp_message msg;
    build_eof(&msg, connection->established_id, connection->is_listener);
    encrypt_stream(auth, connection, &msg);

    send_ping(connection->remote_ip, &msg);
}

static void send_data(const struct encrypt_auth* auth, const struct handshake_established* connection, unsigned short sequence, const unsigned char* data, unsigned short data_sz, unsigned char is_command) {
    struct icmp_message msg;

    if (is_command)
        build_command(&msg, connection->established_id, sequence, data, data_sz, connection->is_listener);
    else
        build_data(&msg, connection->established_id, sequence, data, data_sz, connection->is_listener);

    encrypt_stream(auth, connection, &msg);
    send_ping(connection->remote_ip, &msg);
}

static void process_acknowledgement(void* _state, unsigned short index) {
    struct stream_parse_userdata* state = _state;

    struct window_entry* buffer_entry = find_existing_for_sequence(state->flow->send_window, index);

    state->flow->last_time_acked = time(NULL);

    if (!buffer_entry)
        return;

    memset(buffer_entry, 0, sizeof(struct window_entry));
}

static void reset_keepalive(struct stream_flow_state* flow) {
    flow->last_time_acked = time(NULL);
    flow->sent_keep_alive = 0;
}

static void process_keepalive(void* _state) {
    struct stream_parse_userdata* state = _state;

    send_keepalive(state->auth, state->connection, 1);
}

static void process_eof(void* _state) {
    struct stream_parse_userdata* state = _state;

    state->flow->eof = 1;
}

static void process_data(void* _state, const char* d, unsigned short sz, unsigned short sequence, unsigned char is_command) {
    struct stream_parse_userdata* state = _state;

    unsigned short max_accept_sequence = state->flow->recv_next_writein + WINDOW_SIZE;

    int is_past = 0;
    //Our window is rolling over...
    if (max_accept_sequence > state->flow->recv_next_writein) {
        //If it doesn't fit into our current window, we ignore it.
        if (sequence >= max_accept_sequence)
            return;

        is_past = sequence < state->flow->recv_next_writein;
    } else {
        if (sequence > max_accept_sequence && sequence < state->flow->recv_next_writein)
            return;

        is_past = sequence < state->flow->recv_next_writein && sequence > max_accept_sequence + USHRT_MAX / 2;
    }

    //We've already processed this. Send an acknowledgement;
    if (is_past || find_existing_for_sequence(state->flow->recv_window, sequence)) {
        mark_acknowledge(state->flow, sequence);
        return;
    }

    struct window_entry* dest = find_free_entry(state->flow->recv_window);

    if (dest == 0)
        printf("Rejected data, receive window is full!\n");

    //No room for this data, we ignore it.
    if (!dest)
        return;

    //Otherwise, acknowledge it and populate our destination entry.
    mark_acknowledge(state->flow, sequence);

    dest->occupied = 1;
    memcpy(dest->data, d, sz);
    dest->data_sz = sz;
    dest->elapsed_since_sent = 0;
    dest->index = sequence;
    dest->is_command = is_command;
}

static void process_packets(const struct encrypt_auth* auth, const struct handshake_established* connection, struct icmp_session_context* icmp, struct stream_flow_state* flow) {
    struct icmp_message message;

    struct parse_stream_callback callback = {
        .data = process_data,
        .data_ack = process_acknowledgement,
        .keepalive_ack = NULL, //We can ignore this, because we reset keep alive on any valid receieved message.
        .keepalive = process_keepalive,
        .eof = process_eof
    };

    struct stream_parse_userdata userdata = {
        .flow = flow,
        .connection = connection,
        .auth = auth
    };

    while (icmp_poll(icmp, &message)) {
        decrypt_stream(auth, connection, &message);
        if (parse_stream(connection, &message, &callback, &userdata))
            reset_keepalive(flow);
    }
}

static int logic_recv(struct stream_flow_state* flow, datahead_t* recv_head, datahead_t* cmd_head) {
    struct window_entry* ready_data = 0;
    int data_read = 0;
    while ((ready_data = find_existing_for_sequence(flow->recv_window, flow->recv_next_writein))) {
        datanode_t* n = malloc(sizeof(datanode_t));

        if (!n) {
            fprintf(stderr, "Error allocating data node!\n");
        }

        memcpy(n->data, ready_data->data, ready_data->data_sz);
        n->data_sz = ready_data->data_sz;

        TAILQ_INSERT_TAIL(ready_data->is_command ? cmd_head : recv_head, n, nodes);

        memset(ready_data, 0, sizeof(struct window_entry));
        flow->recv_next_writein++;
        data_read = 1;
    }

    return data_read;
}

static int logic_send(struct stream_flow_state* flow, datahead_t* send_head) {
    int data_queued = 0;
    while (true) {
        //No data to send
        if (TAILQ_EMPTY(send_head))
            break;

        struct window_entry* free_send = find_free_entry(flow->send_window);

        //No room to send data...
        if (!free_send)
            break;

        data_queued = 1;

        struct datanode* e = TAILQ_FIRST(send_head);

        TAILQ_REMOVE(send_head, e, nodes);

        free_send->data_sz = e->data_sz;
        free_send->occupied = 1;
        memcpy(free_send->data, &e->data, e->data_sz);
        free_send->index = flow->send_next_writeout++;

        free_send->elapsed_since_sent = SEND_TIMEOUT_NS * 100;

        free_send->is_command = e->is_command;

        free(e);
    }

    return data_queued;
}

static struct window_entry* select_send_entry(struct stream_flow_state* flow) {
    struct window_entry*  selected = NULL;

    for (unsigned int i = 0; i < WINDOW_SIZE; i++) {
        if (!flow->send_window[i].occupied)
            continue;

        if (flow->send_window[i].elapsed_since_sent < SEND_TIMEOUT_NS)
            continue;

        if (!selected) {
            selected = &flow->send_window[i];
            continue;
        }

        if (flow->send_window[i].index < selected->index) {
            selected = &flow->send_window[i];
        }
    }

    return selected;
}

static int send_packets(const struct encrypt_auth* auth, const struct handshake_established* connection, struct stream_flow_state* flow, unsigned long delta_ns) {
    int sent_packets = 0;

    unsigned long total_elapsed = delta_ns + flow->last_interval_carryover;

    unsigned int dispatch_count = MIN(MAX_SEND_PER_INTERVAL, total_elapsed / DEFAULT_FLOW_INTERVAL_NS);

    flow->last_interval_carryover = MIN(MAX_INTERVAL_CARRYOVER, (total_elapsed % DEFAULT_FLOW_INTERVAL_NS) * DEFAULT_FLOW_INTERVAL_NS);

    for (unsigned int i = 0; i < WINDOW_SIZE; i++) {
        if (flow->send_window[i].occupied)
            flow->send_window[i].elapsed_since_sent += delta_ns;
    }

    for (unsigned int i = 0; i < MAX_SEND_PER_INTERVAL && i < dispatch_count; i++) {
        struct window_entry* e = select_send_entry(flow);
        if (!e)
            break;

        e->elapsed_since_sent = 0;

        sent_packets = 1;

        send_data(
            auth,
            connection,
            e->index,
            e->data,
            e->data_sz,
            e->is_command
        );
    }

    return sent_packets;
}

static int send_acknowledgements_range(const struct encrypt_auth* auth, const struct handshake_established* connection, unsigned short start, unsigned short end) {
    struct icmp_message msg;
    build_acknowledge_range(&msg, connection->established_id, start, end, connection->is_listener);

    encrypt_stream(auth, connection, &msg);
    send_ping(connection->remote_ip, &msg);
    return 1;
}

static int send_acknowledgements_pair(const struct encrypt_auth* auth, const struct handshake_established* connection, unsigned short a, unsigned short b) {
    struct icmp_message msg;
    build_acknowledge_pair(&msg, connection->established_id, a, b, connection->is_listener);

    encrypt_stream(auth, connection, &msg);
    send_ping(connection->remote_ip, &msg);
    return 1;
}

static int send_acknowledgements_single(const struct encrypt_auth* auth, const struct handshake_established* connection, unsigned short sequence) {
    struct icmp_message msg;

    build_acknowledge_single(&msg, connection->established_id, sequence, connection->is_listener);
    encrypt_stream(auth, connection, &msg);

    send_ping(connection->remote_ip, &msg);
    return 1;
}

static int send_acknowledgements(const struct encrypt_auth* auth, const struct handshake_established* connection, struct stream_flow_state* flow) {
    if (flow->recv_window_ack_len == 0)
        return 0;

    qsort(flow->recv_window_ack, flow->recv_window_ack_len, sizeof(unsigned short), compare_uint16);

    int last_stray_id = -1;
    int range_start = -1;
    for (int i = 0; i < flow->recv_window_ack_len; i++) {
        if (range_start > 0) {
            //we are in a range
            int last_idx = i - 1;
            if (flow->recv_window_ack[i] - flow->recv_window_ack[last_idx] == 1) {
                //this new item is a member of the range...
                continue;
            } else {
                //Our range ends here...
                send_acknowledgements_range(auth, connection, flow->recv_window_ack[range_start], flow->recv_window_ack[last_idx]);
                range_start = -1;
            }
        }

        int is_range_start = i < flow->recv_window_ack_len - 1
                          && flow->recv_window_ack[i + 1] - flow->recv_window_ack[i] == 1;

        if (is_range_start) {
            range_start = i;
        } else {
            //It is a stray. Can we pair it?
            if (last_stray_id > 0) {
                send_acknowledgements_pair(auth, connection, flow->recv_window_ack[i], flow->recv_window_ack[last_stray_id]);
                last_stray_id = -1;
            } else {
                last_stray_id = i;
            }
        }
    }

    if (last_stray_id >= 0) {
        send_acknowledgements_single(auth, connection, flow->recv_window_ack[last_stray_id]);
    }

    if (range_start >= 0) {
        send_acknowledgements_range(auth, connection, flow->recv_window_ack[range_start], flow->recv_window_ack[flow->recv_window_ack_len - 1]);
    }

    flow->recv_window_ack_len = 0;
    return 1;
}

static void initialize_flow(struct stream_flow_state* flow) {
    flow->recv_next_writein = 0;
    flow->send_next_writeout = 0;
    flow->last_time_acked = time(NULL);
    flow->eof = 0;
    flow->recv_window_ack_len = 0;

    memset(flow->recv_window, 0, sizeof(flow->recv_window));
    memset(flow->send_window, 0, sizeof(flow->send_window));
}

static void logic_keepalive(const struct encrypt_auth* auth, const struct handshake_established* connection, struct stream_flow_state* flow) {
    unsigned long delta = time(NULL) - flow->last_time_acked;

    int send_keep_alive = delta > STREAM_KEEPALIVE_THRESHOLD
                        && flow->sent_keep_alive < MAX_SEND_KEEPALIVE
                        && delta % KEEPALIVE_TRANSIT_INTERVAL == 0;

    if (send_keep_alive) {
        send_keepalive(auth, connection, 0);
    } else {
        flow->sent_keep_alive = 0;
    }
}

static void* send_recv_loop(void* _session) {
    struct stream_daemon_ctx* session = _session;

    struct stream_flow_state flow;

    initialize_flow(&flow);

    pthread_mutex_lock(session->session_ctx->io_mutex);

    unsigned long delta_ns = 0;
    struct timespec timestamp_delta_measurement[2];
    int timestamp_cursor = 0;

    clock_gettime(CLOCK_MONOTONIC, &timestamp_delta_measurement[timestamp_cursor % 2]);

    for(unsigned long i = 0; !session->session_ctx->closed && !flow.eof; i++) {
        if (atomic_load(&session->session_ctx->pending_read) || atomic_load(&session->session_ctx->pending_write)) {
            pthread_cond_wait(session->session_ctx->io_cond, session->session_ctx->io_mutex);
        }

        process_packets(session->auth, session->connection, session->icmp, &flow);

        int loop_was_effective = 0;
        if (logic_recv(&flow, session->session_ctx->recv_head, session->session_ctx->recv_cmd_head)) {
            if (!TAILQ_EMPTY(session->session_ctx->recv_head))
                atomic_store(&session->session_ctx->data_to_read, 1);

            if (!TAILQ_EMPTY(session->session_ctx->recv_cmd_head))
                atomic_store(&session->session_ctx->command_to_read, 1);

            loop_was_effective = 1;
        }


        loop_was_effective |= logic_send(&flow, session->session_ctx->send_head);

        int next_timestamp_cursor = (timestamp_cursor + 1) % 2;
        clock_gettime(CLOCK_MONOTONIC, &timestamp_delta_measurement[next_timestamp_cursor]);
        long delta = elapsed_clock(&timestamp_delta_measurement[timestamp_cursor], &timestamp_delta_measurement[next_timestamp_cursor]);

        timestamp_cursor = next_timestamp_cursor;
        loop_was_effective |= send_packets(session->auth, session->connection, &flow, delta);
        send_acknowledgements(session->auth, session->connection, &flow);

        if (!session->disable_heartbeat) {
            int is_alive = time(NULL) - flow.last_time_acked <= STREAM_DEAD_THRESHOLD;
            logic_keepalive(session->auth, session->connection, &flow);
            atomic_store(&session->session_ctx->heartbeat_alive, is_alive);
        }

        if (!loop_was_effective)
            yield_ns(DEFAULT_FLOW_INTERVAL_NS / 10);
    }

    pthread_mutex_unlock(session->session_ctx->io_mutex);

    send_eof(session->auth,session->connection);

    atomic_store(&session->session_ctx->heartbeat_alive, 0);
    atomic_store(&session->session_ctx->closed, 1);

    return session;
}

void stream_close(struct stream_session_context* ctx) {
    atomic_store(&ctx->closed, 1);
}

static void do_stream_start(void* _ctx, struct icmp_session_context* icmp) {
    struct stream_icmp_userdata* ctx = _ctx;

    static pthread_t send_recv_thread;
    static pthread_mutex_t io_mutex = PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t io_cond = PTHREAD_COND_INITIALIZER;

    datahead_t send_head;
    datahead_t recv_head;
    datahead_t recv_cmd_head;

    TAILQ_INIT(&send_head);
    TAILQ_INIT(&recv_head);
    TAILQ_INIT(&recv_cmd_head);

    struct stream_session_context session_ctx = {
        .recv_head = &recv_head,
        .send_head = &send_head,
        .recv_cmd_head = &recv_cmd_head,
        .io_mutex = &io_mutex,
        .io_cond = &io_cond,
        .heartbeat_alive = ATOMIC_VAR_INIT(1),
        .closed = ATOMIC_VAR_INIT(0),
        .data_to_read = ATOMIC_VAR_INIT(0),
        .pending_read = ATOMIC_VAR_INIT(0),
        .pending_write = ATOMIC_VAR_INIT(0),
        .command_to_read = ATOMIC_VAR_INIT(0)
    };

    struct stream_daemon_ctx daemon_ctx = {
        .connection = ctx->established,
        .session_ctx = &session_ctx,
        .icmp = icmp,
        .disable_heartbeat = ctx->disable_heartbeat,
        .auth = ctx->auth
    };

    pthread_create(&send_recv_thread, NULL, send_recv_loop, &daemon_ctx);

    ctx->session(ctx->userdata, &session_ctx);

    stream_close(&session_ctx);

    pthread_join(send_recv_thread, NULL);
}

int stream_is_alive(struct stream_session_context* ctx) {
    return atomic_load(&ctx->heartbeat_alive) && !atomic_load(&ctx->closed);
}

void stream_start(const struct encrypt_auth* auth, const struct handshake_established* established, stream_session session, int disable_heartbeat, void* userdata) {
    struct stream_icmp_userdata data = {
        .established = established,
        .session = session,
        .userdata = userdata,
        .disable_heartbeat = disable_heartbeat,
        .auth = auth
    };

    icmp_monitor(do_stream_start, &data);
}

ssize_t stream_read(struct stream_session_context* ctx, char* buffer, const size_t buffer_sz) {
    if(buffer_sz % DATA_CHUNK_SZ) {
        fprintf(stderr, "Buffer size must be a multiple of DATA_CHUNK_SZ.");
        return -1;
    }

    if (!atomic_load(&ctx->data_to_read))
        return 0;

    atomic_store(&ctx->pending_read, 1);

    pthread_mutex_lock(ctx->io_mutex);
    pthread_cond_signal(ctx->io_cond);

    unsigned int num_chunks = buffer_sz / DATA_CHUNK_SZ;

    char* write_dest = buffer;

    for(unsigned int i = 0; i < num_chunks; i++) {
        if(TAILQ_EMPTY(ctx->recv_head))
            break;

        struct datanode* e = TAILQ_FIRST(ctx->recv_head);

        TAILQ_REMOVE(ctx->recv_head, e, nodes);

        memcpy(write_dest, e->data, e->data_sz);
        write_dest += e->data_sz;

        free(e);
    }

    if(TAILQ_EMPTY(ctx->recv_head)) {
        atomic_store(&ctx->data_to_read, 0);
    }

    atomic_store(&ctx->pending_read, 0);
    pthread_mutex_unlock(ctx->io_mutex);

    ssize_t data_read = write_dest - buffer;

    return data_read;
}

static ssize_t stream_write_internal(struct stream_session_context* ctx, const char* buffer, const size_t buffer_sz, unsigned char is_command) {
    if(buffer_sz == 0)
        return 0;

    atomic_store(&ctx->pending_write, 1);
    pthread_mutex_lock(ctx->io_mutex);
    pthread_cond_signal(ctx->io_cond);

    for(unsigned int to_write = buffer_sz; to_write > 0;) {
        struct datanode* n = malloc(sizeof(struct datanode));

        if (!n) {
            fprintf(stderr, "Error allocating data node!\n");
        }

        const unsigned int write_sz = to_write > DATA_CHUNK_SZ ? DATA_CHUNK_SZ : to_write;
        memcpy(n->data, &buffer[buffer_sz - to_write], write_sz);
        n->data_sz = write_sz;
        n->is_command = is_command;

        to_write -= write_sz;

        TAILQ_INSERT_TAIL(ctx->send_head, n, nodes);
    }

    atomic_store(&ctx->pending_write, 0);

    pthread_mutex_unlock(ctx->io_mutex);

    return buffer_sz;
}

ssize_t stream_write(struct stream_session_context* ctx, const char* buffer, const size_t buffer_sz) {
    return stream_write_internal(ctx, buffer, buffer_sz, 0);
}

void stream_command(struct stream_session_context* ctx, unsigned char command)
{
    stream_write_internal(ctx, (char*)&command, 1, 1);
}

int stream_poll_cmd(struct stream_session_context* ctx, unsigned short* cmd) {
    if (!atomic_load(&ctx->command_to_read))
        return 0;

    atomic_store(&ctx->pending_read, 1);

    pthread_mutex_lock(ctx->io_mutex);
    pthread_cond_signal(ctx->io_cond);

    int collected_command = 0;

    if(!TAILQ_EMPTY(ctx->recv_cmd_head))
    {
        struct datanode* e = TAILQ_FIRST(ctx->recv_cmd_head);

        TAILQ_REMOVE(ctx->recv_cmd_head, e, nodes);

        *cmd = *((uint16_t*)e->data) & 0xFF;
        collected_command = 1;
        free(e);
    }

    if(TAILQ_EMPTY(ctx->recv_cmd_head)) {
        atomic_store(&ctx->command_to_read, 0);
    }

    atomic_store(&ctx->pending_read, 0);
    pthread_mutex_unlock(ctx->io_mutex);

    return collected_command;;
}