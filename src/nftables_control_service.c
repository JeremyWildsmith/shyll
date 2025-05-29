#include "nftables_control_service.h"
#include "cncdaemon.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "keyboard.h"
#include "knocking.h"
#include "nftables.h"

#define MAX_SUPPORTED_NFT_RULES 5

static const char* nftables_recovery_file = "/var/run/shyll.nftrecovery";

struct nftables_control_service_ctx
{
    struct knock_context knock;
    pthread_t thread;
    atomic_bool queue_end;
    int is_tables_open;
    unsigned int knock_window_length_s;
};

void update_table_state(struct nftables_control_service_ctx* ctx, struct nft_rule* rules, size_t* rules_len, int is_open)
{
    if (ctx->is_tables_open == is_open)
        return;

    ctx->is_tables_open = is_open;

    printf("NFTables Port Knocking status set to: %s\n", is_open ? "open" : "closed");

    if (is_open)
    {
        *rules_len = nft_query_icmp_echo_rules(rules,  MAX_SUPPORTED_NFT_RULES);

        if (*rules_len == 0)
        {
            fprintf(stderr, "Warning, no ICMP echo rules were found. This means port-knocking isn't effective.");
            fprintf(stderr, "You can add an NFT ICMP Echo rule like so:\n");
            fprintf(stderr, "\tnft add rule ip filter INPUT icmp type echo-request drop\n");
        }

        if (!nft_backup_rules(rules, *rules_len, nftables_recovery_file))
        {
            fprintf(stderr, "Error, not updating NFT in response to port knocking, unable to backup rules.");
            return;
        }

        nft_delete_rules(rules, *rules_len);
    } else
    {
        nft_restore_rules(nftables_recovery_file);
    }
}

static void* nftables_control_logic_loop(void* _ctx)
{
    struct nft_rule rules[MAX_SUPPORTED_NFT_RULES];
    size_t rules_len = 0;

    struct nftables_control_service_ctx* ctx = _ctx;

    while (!atomic_load(&ctx->queue_end))
    {
        int should_be_open = 0;
        unsigned long last_open = knocking_last_open(&ctx->knock);

        if (last_open)
            should_be_open = time(NULL) - last_open < ctx->knock_window_length_s;

        update_table_state(ctx, rules, &rules_len, should_be_open);

        sleep(1);
    }

    return _ctx;
}

static int nftables_entry(void* _ctx, char** argv, int argc, FILE* command_out)
{
    return 0;
}

void nftables_control_startup(struct encrypt_auth* auth, unsigned int knock_window_length_s, struct cncdaemon_service* dest)
{
    struct nftables_control_service_ctx* ctx = malloc(sizeof(struct nftables_control_service_ctx));
    ctx->queue_end = ATOMIC_VAR_INIT(0);
    ctx->is_tables_open = 0;
    ctx->knock_window_length_s = knock_window_length_s;

    dest->userdata = ctx;
    dest->handler = nftables_entry;


    if (!knock_startup(auth, &ctx->knock))
    {
        fprintf(stderr, "Error starting knocking daemon service. Terminating...\n");
        exit(1);
    }

    pthread_create(&ctx->thread, NULL, nftables_control_logic_loop, ctx);
}

void nftables_control_shutdown(struct cncdaemon_service* service)
{
    struct nftables_control_service_ctx* ctx = service->userdata;
    atomic_store(&ctx->queue_end, 1);

    pthread_join(ctx->thread, NULL);

    knock_shutdown(&ctx->knock);

    free(service);
}