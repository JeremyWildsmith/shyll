#pragma once

#define MAX_NFTABLES_CLAUSE_LEN 2048
#define MAX_NFT_NAME_LEN 256
#include <stddef.h>

struct nft_rule
{
    int handle;
    char table[MAX_NFT_NAME_LEN];
    char chain[MAX_NFT_NAME_LEN];
    char definition[MAX_NFTABLES_CLAUSE_LEN * 4];
};

int nft_query_icmp_echo_rules(struct nft_rule* buffer, size_t len);
void nft_restore_rules(const char* source_file);
int nft_backup_rules(const struct nft_rule* rules, const size_t rules_len, const char* dest);
void nft_delete_rules(struct nft_rule* rules, const size_t rules_len);
