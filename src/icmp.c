#include "icmp.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <memory.h>
#include <sys/param.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/poll.h>

#include "util.h"


typedef struct icmpnode
{
    struct icmp_message m;
    TAILQ_ENTRY(icmpnode) nodes;
} icmpnode_t;

typedef TAILQ_HEAD(icmphead_s, icmpnode) icmphead_t;

struct icmp_session_context {
    icmphead_t* head;
    volatile int* queue_end;
    pthread_mutex_t* queue_mutex;
    pthread_cond_t* queue_cond;

    atomic_bool pending_read;
    atomic_bool data_ready;
};

static ssize_t receieve_ip(const int s, char* result, const int result_sz) {
    char icmp_buffer[65536];

    if(result_sz < sizeof(struct iphdr))
        return -1;

    struct pollfd stdin_poll = {
        .fd = s,
        .events = POLLIN,
        .revents = 0
    };

    if (poll(&stdin_poll, 1, 0) < 0 || (stdin_poll.revents & POLLIN) == 0)
        return 0;

    const ssize_t read_bytes = recv(s, icmp_buffer, sizeof(icmp_buffer), 0);

    if(read_bytes < 0)
        return read_bytes;

    memcpy(result, icmp_buffer, MIN(read_bytes, result_sz));

    return read_bytes;
}

static unsigned short sum_icmp(const char* payload, const unsigned int sz_bytes) {
    unsigned int sum = 0;

    for(unsigned int i = 0; i < sz_bytes / 2; i++)
        sum += ((unsigned short*)payload)[i];

    if(sz_bytes % 2 == 1)
        sum += payload[sz_bytes - 1];

    return sum;
}

static unsigned short checksum_icmp(const char* payload, const unsigned int sz_bytes) {
    unsigned int sum = sum_icmp(payload, sz_bytes);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static unsigned int compile_icmp(const struct icmp_message* message, char* dest, const unsigned int destSz) {
    const unsigned int required_size = message->payload_sz + sizeof(struct icmphdr);

    if(required_size > destSz || required_size == 0)
        return 0;

    memset(dest, 0, sizeof(struct icmphdr));
    memcpy(dest + sizeof(struct icmphdr), message->payload_buffer, message->payload_sz);

    struct icmphdr* hdr = (struct icmphdr*) dest;

    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->un.echo.id = message->id;
    hdr->un.echo.sequence = message->sequence;
    hdr->checksum = 0;

    const unsigned short checksum = checksum_icmp(dest, required_size);

    hdr->checksum = checksum;
    //printf("chksm(%d): %d\n", required_size, checksum);

    return required_size;
}

unsigned short compute_checksum(const struct icmp_message* message) {
    char b[4096];

    compile_icmp(message, b, sizeof(b));

    return ((struct icmphdr*)b)->checksum;
}

uint16_t icmp_compute_checksum_delta(const struct icmp_message* message, const unsigned short target_checksum) {
    const unsigned int required_size = message->payload_sz + sizeof(struct icmphdr);

    char* dest = malloc(required_size);

    if(!dest) {
        fprintf(stderr, "Error allocaing ICMP buffer space.");
        exit(0);
    }

    memset(dest, 0, sizeof(struct icmphdr));
    memcpy(dest + sizeof(struct icmphdr), message->payload_buffer, message->payload_sz);

    struct icmphdr* hdr = (struct icmphdr*) dest;

    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->un.echo.id = message->id;
    hdr->un.echo.sequence = message->sequence;

    const uint16_t current_sum = sum_icmp(dest, required_size);

    uint16_t trail = (~target_checksum - current_sum) & 0xFFFF;

    free(dest);

    return trail;
}

static int create_socket(const unsigned short ttl) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(s == -1) {
        fprintf(stderr, "Unable to construct ICMP socket. May not have sufficient permissions? (errno = %d)\n", errno);
        return -1;
    }

    if(setsockopt(s, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        fprintf(stderr, "Unable to configure TTL field to: %d.\n", ttl);
        close(s);
        return -1;
    }

    return s;
}

unsigned int send_ping(const char* addr_name, const struct icmp_message* message) {
    const unsigned int total_size = sizeof(struct icmphdr) + message->payload_sz;
    unsigned char raw_buffer[total_size];
    struct sockaddr_in addr;

    if(!create_address(addr_name, &addr)) {
        return 0;
    }

    const int s = create_socket(message->ttl);

    if(s < 0) {
        return 0;
    }

    if(!compile_icmp(message, raw_buffer, sizeof(raw_buffer))) {
        fprintf(stderr, "Error building the ICMP packet.\n");
        close(s);
        return 0;
    }

    if(sendto(s, raw_buffer, total_size, 0, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        fprintf(stderr, "Error transmitting ICMP packet.\n");
        close(s);
        return 0;
    }

    close(s);

    return total_size;
}

int receive_icmp(struct icmp_session_context* ctx, const process_icmp handler, const volatile int* stop_test)
{
    char buffer[65536];
    const int s = create_socket(255);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if(s == -1) {
        fprintf(stderr, "Unable to create socket to listen on.\n");
        return 0;
    }

    const unsigned int total_header_len = sizeof(struct iphdr) + sizeof(struct icmphdr);

    pthread_mutex_lock(ctx->queue_mutex);
    while(!*stop_test) {
        if (atomic_load(&ctx->pending_read)) {
            pthread_cond_wait(ctx->queue_cond, ctx->queue_mutex);
        }

        const ssize_t read = receieve_ip(s, buffer, sizeof(buffer));

        //Ignore error conditions / invalid packets.
        if(read <= 0 || read < total_header_len) {
            yield_proc();
            continue;
        }

        struct iphdr* iphdr = (struct iphdr*)(buffer);
        struct icmphdr* hdr = (struct icmphdr*)(&buffer[sizeof(struct iphdr)]);

        if(hdr->type != ICMP_ECHO && hdr->type != ICMP_ECHOREPLY)
            continue;

        const int is_reply = hdr->type == ICMP_ECHOREPLY;

        unsigned int payload_sz = read - total_header_len;
        const char* payload = buffer + total_header_len;

        char ip_buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iphdr->saddr, ip_buffer, sizeof(ip_buffer));

        handler(ctx, ip_buffer, hdr->un.echo.sequence, hdr->un.echo.id, hdr->checksum, is_reply, iphdr->ttl, payload, payload_sz);
    }
    pthread_mutex_unlock(ctx->queue_mutex);

    close(s);

    return 1;
}

static void store(struct icmp_session_context* ctx, struct icmp_message* message) {
    struct icmpnode * e = malloc(sizeof(struct icmpnode));
    if (e == NULL)
    {
        fprintf(stderr, "malloc failed");
        exit(1);
    }

    memcpy(&e->m, message, sizeof(struct icmp_message));

    TAILQ_INSERT_TAIL(ctx->head, e, nodes);
}

static void handle_recv(void* _ctx, const char* sender_ip, const unsigned short sequence, const unsigned short id, const unsigned short checksum, const int is_reply, const unsigned char ttl, const char* payload_buffer, const unsigned int payload_buffer_sz) {
    struct icmp_session_context* ctx = _ctx;
    struct icmp_message m = {
        .id = id,
        .is_reply = is_reply,
        .sequence = sequence,
        .ttl = ttl,
        .checksum = checksum,
        .payload_sz = payload_buffer_sz
    };

    memcpy(m.payload_buffer, payload_buffer, payload_buffer_sz);
    strncpy(m.sender_ip, sender_ip, INET_ADDRSTRLEN);

    store(ctx, &m);

    atomic_store(&ctx->data_ready, 1);
}

static void* recv_loop(void* _ctx) {
    struct icmp_session_context* ctx = _ctx;

    receive_icmp(ctx, handle_recv, ctx->queue_end);

    return ctx;
}

int icmp_poll(struct icmp_session_context* ctx, struct icmp_message* dest) {
    if (!atomic_load(&ctx->data_ready))
        return 0;

    atomic_store(&ctx->pending_read, 1);

    pthread_mutex_lock(ctx->queue_mutex);
    pthread_cond_signal(ctx->queue_cond);

    if(!TAILQ_EMPTY(ctx->head)) {
        struct icmpnode* e = TAILQ_FIRST(ctx->head);

        TAILQ_REMOVE(ctx->head, e, nodes);

        memcpy(dest, &e->m, sizeof(struct icmp_message));

        free(e);

        if (TAILQ_EMPTY(ctx->head))
            atomic_store(&ctx->data_ready, 0);
    } else {
        atomic_store(&ctx->data_ready, 0);
    }

    atomic_store(&ctx->pending_read, 0);
    pthread_mutex_unlock(ctx->queue_mutex);
    return 1;
}

void icmp_monitor(icmp_session session, void* userdata) {
    volatile int  queue_end = 0;
    pthread_t recv_thread;
    pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

    icmphead_t head;

    TAILQ_INIT(&head);

    struct icmp_session_context ctx = {
        .queue_end = &queue_end,
        .head = &head,
        .queue_mutex = &queue_mutex,
        .queue_cond = &queue_cond,
        .pending_read = ATOMIC_VAR_INIT(0),
        .data_ready = ATOMIC_VAR_INIT(0)
    };

    pthread_create(&recv_thread, NULL, recv_loop, &ctx);

    session(userdata, &ctx);

    queue_end = 1;
    pthread_join(recv_thread, NULL);
}

int pad_for_checksum(struct icmp_message* message, const uint16_t target_checksum) {
    unsigned short trailing = icmp_compute_checksum_delta(message, target_checksum);

    const unsigned int padding_size = 2 + message->payload_sz % 2;

    if (padding_size + message->payload_sz > sizeof(message->payload_buffer))
        return 0;

    char* trailing_dest = message->payload_buffer + message->payload_sz;

    message->payload_sz += padding_size;

    if(padding_size % 2) {
        *trailing_dest = 0;
        trailing_dest++;
    }

    *(unsigned short*)trailing_dest = trailing;

    message->is_padded = 1;

    return 1;
}

void truncate_padding_for_checksum(struct icmp_message* message) {
    if (!message->is_padded)
        return;

    if (message->payload_sz < sizeof(uint16_t)) {
        fprintf(stderr, "Assertion error, message incorrectly marked as padded.\n");
        exit(1);
    }

    unsigned int new_size = message->payload_sz - sizeof(uint16_t);
    *((uint16_t*)(&message->payload_buffer[new_size])) = 0;
    message->payload_sz = new_size;

    message->is_padded = 0;
}