#include "nftables.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

static void read_nft_name(char* dest, const char* name_start)
{
    dest[0] = 0;

    const char* name_end = strchr(name_start, '{');

    if (!name_end)
        return;

    int name_len = MIN(name_end - name_start, MAX_NFT_NAME_LEN);
    strncpy(dest, name_start, name_len);
    dest[name_len] = 0;

    name_len -= 1;

    for (; name_len >= 0 && dest[name_len] == ' '; name_len--)
    {
        dest[name_len] = 0;
    }
}

int nft_query_icmp_echo_rules(struct nft_rule* buffer, size_t len) {
    char line_buffer[MAX_NFTABLES_CLAUSE_LEN];
    char table_def[MAX_NFTABLES_CLAUSE_LEN];
    char chain_def[MAX_NFTABLES_CLAUSE_LEN];

    char table_name[MAX_NFT_NAME_LEN];
    char chain_name[MAX_NFT_NAME_LEN];

    FILE* proc = popen("nft --handle list ruleset", "r");

    if (!proc)
    {
        fprintf(stderr, "Failed to list nft rules.\n");
        return 0;
    }

    int last_rule_index = -1;

    while (last_rule_index + 1 < len && fgets(line_buffer, sizeof(line_buffer), proc))
    {
        if (table_def[0] == 0)
        {
            const char* token = "table ";
            const char* def_idx = strstr(line_buffer, token);

            if (!def_idx)
                continue;

            strcpy(table_def, def_idx);
            read_nft_name(table_name, def_idx + strlen(token));

        } else if (chain_def[0] == 0)
        {
            const char* token = "chain ";
            const char* def_idx = strstr(line_buffer, token);

            if (!def_idx)
                continue;

            strcpy(chain_def, def_idx);
            read_nft_name(chain_name, def_idx + strlen(token));
        } else if (strchr(line_buffer, '}'))
        {
            if (chain_def[0] != 0)
                chain_def[0] = 0;
            else if (table_def[0] != 0)
                table_def[0] = 0;
        } else if (strstr(line_buffer, "icmp"))
        {
            //this is an ICMP rule...
            char* handle_def = strstr(line_buffer, "# handle ");
            int rule_no;
            if (handle_def &&
                sscanf(handle_def, "# handle %d", &rule_no) == 1)
            {
                last_rule_index++;
                strcpy(buffer[last_rule_index].table, table_name);
                strcpy(buffer[last_rule_index].chain, chain_name);

                strcpy(buffer[last_rule_index].definition, table_def);
                strcat(buffer[last_rule_index].definition, chain_def);
                strcat(buffer[last_rule_index].definition, line_buffer);
                strcat(buffer[last_rule_index].definition, "}\n}");
            }
        }
    }

    fclose(proc);

    return last_rule_index + 1;
}


void nft_restore_rules(const char* source_file)
{
    char command_buffer[MAXPATHLEN * 2];
    sprintf(command_buffer, "nft -f \"%s\"", source_file);

    int result = system(command_buffer);

    if (result != 0)
    {
        fprintf(stderr, "Error recovering nft rules...\n");
    }
}

int nft_backup_rules(const struct nft_rule* rules, const size_t rules_len, const char* dest)
{
    FILE* recovery_file = fopen(dest, "w+");

    if (!recovery_file)
    {
        fprintf(stderr, "Error updating NFT Rules, unable to write to recovery file %s\n", dest);
        return 0;
    }

    for (int i = 0; i < rules_len; i++)
    {
        fputs(rules[i].definition, recovery_file);
        fputs("\n", recovery_file);
    }

    fclose(recovery_file);

    return 1;
}

void nft_delete_rules(struct nft_rule* rules, const size_t rules_len)
{
    for (int i = 0; i < rules_len; i++)
    {
        char command[MAX_NFTABLES_CLAUSE_LEN * 3] = {0};
        snprintf(command, sizeof(command), "nft delete rule %s %s handle %d", rules[i].table, rules[i].chain, rules[i].handle);

        int result = system(command);

        if (result != 0)
        {
            fprintf(stderr, "Error deleting NFTable rule (handle %d); Skipping.\n", rules[i].handle);
        }
    }
}
