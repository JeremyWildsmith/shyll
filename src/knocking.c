#include "knocking.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

static unsigned short PRIVATE_UDP_PORT_RANGE_BEGIN = 49152;
static unsigned short PRIVATE_UDP_PORT_RANGE_END = 65535;

static unsigned long KNOCK_INTERVAL_MAX_S = 100000;

static void reset_knock_recv(struct knock_context* ctx)
{
    for (int i = 0; i < KNOCK_SEQUENCE_LENGTH; i++)
    {
        ctx->recv_knock_sizes[i] = 0;
        ctx->recv_knock_times[i] = 0;
    }
}

static int process_tcpdump_port(struct knock_context* ctx, const char* entry)
{
    char* start_of_dest = strstr(entry, " > ");

    if (!start_of_dest)
        return -1;

    start_of_dest += 3;

    int ip_a, ip_b, ip_c, ip_d, port;

    int read_fields = sscanf(start_of_dest, "%d.%d.%d.%d.%d", &ip_a, &ip_b, &ip_c, &ip_d, &port);

    if (read_fields != 5)
        return -1;

    return port;
}


static int process_tcpdump_length(struct knock_context* ctx, const char* entry)
{
    const char* token = "length ";
    char* start_of_dest = strstr(entry, token);

    if (!start_of_dest)
        return -1;

    start_of_dest += strlen(token);

    int len;

    int read_fields = sscanf(start_of_dest, "%d)", &len);

    if (read_fields != 1)
        return -1;

    return len;
}

static void record_tcpdump_entry(struct knock_context* ctx, const unsigned short port, int data_size)
{
    int i = 0;
    for (; i < KNOCK_SEQUENCE_LENGTH; i++)
    {
        if (ctx->knock_ports[i] == port)
            break;
    }

    if (i >= KNOCK_SEQUENCE_LENGTH)
        return;

    ctx->recv_knock_times[i] = time(NULL);
    ctx->recv_knock_sizes[i] = data_size;
}

static int test_knocking_satisfied(const struct knock_context* ctx)
{
    for (int i = 0; i < KNOCK_SEQUENCE_LENGTH; i++)
    {
        if (time(NULL) - ctx->recv_knock_times[i] > KNOCK_INTERVAL_MAX_S)
            return 0;

        for (int w = i + 1; w < KNOCK_SEQUENCE_LENGTH; w++)
        {
            if (ctx->recv_knock_sizes[i] >= ctx->recv_knock_sizes[i + 1])
                return 0;
        }
    }

    return 1;
}

static void* knocking_logic(void* _ctx)
{
    char line_buffer[4096];
    struct knock_context* ctx = _ctx;

    while (1)
    {
        if (!fgets(line_buffer, sizeof(line_buffer), ctx->tcpdump))
            break;

        int len = process_tcpdump_length(ctx, line_buffer);

        if (len < 0)
            continue;

        if (!fgets(line_buffer, sizeof(line_buffer), ctx->tcpdump))
            break;

        int port = process_tcpdump_port(ctx, line_buffer);

        if (port < 0)
            continue;

        record_tcpdump_entry(ctx, port, len);

        if (test_knocking_satisfied(ctx))
        {
            printf("Knock pattern as been receieved.\n");
            reset_knock_recv(ctx);
            atomic_store(&ctx->knock_time, time(NULL));
        }
    }

    return ctx;
}

static FILE* spawn_tcpdump()
{
    //tcmp -i any --direction=in -nn udp
    //53 is the desitnation port...
    //08:28:35.053909 lo    In  IP 127.0.0.1.35310 > 127.0.0.53.53: 3398+ [1au] AAAA? dns.shaw.ca. (40)

    FILE* proc = popen("tcpdump -v -l -i any --direction=in -nn udp", "r");

    if (!proc)
    {
        fprintf(stderr, "Failed to run tcpdump to monitor for port knock sequence.\n");
        return NULL;
    }

    return proc;
}

static void initialize_knock_sequence(const struct encrypt_auth* auth, unsigned short knock_ports[KNOCK_SEQUENCE_LENGTH])
{
    knock_ports[0] = auth->key_seed[0] & 0xFFFF;
    knock_ports[1] = (auth->key_seed[0] >> 16) & 0xFFFF;

    knock_ports[2] = auth->key_seed[1] & 0xFFFF;
    knock_ports[3] = (auth->key_seed[1] >> 16) & 0xFFFF;

    knock_ports[4] = auth->key_seed[2] & 0xFFFF;
    knock_ports[5] = (auth->key_seed[2] >> 16) & 0xFFFF;

    knock_ports[6] = auth->key_seed[3] & 0xFFFF;
    knock_ports[7] = (auth->key_seed[3] >> 16) & 0xFFFF;

    //enforce all ports to be in private range to avoid interference
    for (int i = 0; i < 8; i++)
        knock_ports[i] = PRIVATE_UDP_PORT_RANGE_BEGIN + knock_ports[i] % (PRIVATE_UDP_PORT_RANGE_END - PRIVATE_UDP_PORT_RANGE_BEGIN);
}

int knock_startup(const struct encrypt_auth* auth, struct knock_context* ctx)
{
    FILE* proc = spawn_tcpdump();

    if (!proc)
        return 0;

    initialize_knock_sequence(auth, ctx->knock_ports);
    reset_knock_recv(ctx);
    ctx->knock_time = ATOMIC_VAR_INIT(0);
    ctx->tcpdump = proc;
    pthread_create(&ctx->thread, NULL, knocking_logic, ctx);

    return 1;
}

void knock_shutdown(const struct knock_context* ctx)
{
    fclose(ctx->tcpdump);
    pthread_join(ctx->thread, NULL);
}

unsigned long knocking_last_open(const struct knock_context* ctx)
{
    unsigned long knock_time = atomic_load(&ctx->knock_time);

    return knock_time;
}

void knock_send(const struct encrypt_auth* auth, const char* remote)
{
    unsigned short dest_ports[KNOCK_SEQUENCE_LENGTH];
    initialize_knock_sequence(auth, dest_ports);

    int last_size = 0;
    char data_buffer[1024];

    const int max_increment = sizeof(data_buffer) / KNOCK_SEQUENCE_LENGTH;

    struct sockaddr_in dest;
    create_address(remote, &dest);

    int s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s < 0)
    {
        fprintf(stderr, "Could not send knock. Error opening sockket.\n");
        return;
    }

    for (int i = 0; i < KNOCK_SEQUENCE_LENGTH; i++)
    {
        dest.sin_port = htons(dest_ports[i]);

        int size = 1 + last_size + (random() % (max_increment - 1));

        for (int d = 0; d < size; d++)
        {
            data_buffer[d] = (char)('a' + (char)(random() % 26));
        }

        if (sendto(s, data_buffer, size, 0, (struct sockaddr*)&dest, sizeof(struct sockaddr_in)) < 0)
        {
            perror("UCould not send knock.");
            break;
        }

        last_size = size;
    }

    close(s);
}