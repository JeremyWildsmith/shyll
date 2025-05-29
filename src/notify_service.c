#include "notify_service.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/inotify.h>

#define MAX_WATCHES 64

struct notify_watch_entry
{
    char file[MAXPATHLEN];
    int wd;
};

struct notify_service_ctx
{
    int notify_fd;
    pthread_t thread;
    atomic_bool queue_end;

    struct notify_watch_entry watches[MAX_WATCHES];

    FILE* log_file;
    char log_file_name[MAXPATHLEN];


    pthread_mutex_t watch_lock;
};

static struct notify_watch_entry* find_watch(struct notify_service_ctx* cfg, int wd)
{
    for (int i = 0; i < sizeof(cfg->watches) / sizeof(struct notify_watch_entry); i++)
    {
        if (cfg->watches[i].wd == wd)
            return &cfg->watches[i];
    }

    return NULL;
}

static int add_watch(struct notify_service_ctx* cfg, const char* file)
{
    struct notify_watch_entry* free_entry = NULL;;
    for (int i = 0; i < sizeof(cfg->watches) / sizeof(struct notify_watch_entry); i++)
    {
        if (cfg->watches[i].file[0] == 0)
        {
            if (!free_entry)
                free_entry = &cfg->watches[i];
            continue;
        }

        if (strcmp(file, cfg->watches[i].file) == 0)
            return 1;
    }

    if (!free_entry)
        return 0;

    const int wd = inotify_add_watch(cfg->notify_fd, file, IN_CLOSE_WRITE | IN_ATTRIB | IN_IGNORED);

    if (wd == -1)
        return 0;

    strncpy(free_entry->file, file, sizeof(free_entry->file));
    free_entry->wd = wd;

    return 1;
}

static void remove_watch(struct notify_service_ctx* cfg, const char* file)
{
    for (int i = 0; i < sizeof(cfg->watches) / sizeof(struct notify_watch_entry); i++)
    {
        if (cfg->watches[i].file[0] == 0)
            continue;

        if (strcmp(file, cfg->watches[i].file) == 0)
        {
            inotify_rm_watch(cfg->notify_fd, cfg->watches[i].wd);
            cfg->watches[i].file[0] = 0;
            cfg->watches[i].wd = 0;
            return;
        }
    }
}


static void update_watch(struct notify_service_ctx* ctx, struct notify_watch_entry* w)
{
    char path[MAXPATHLEN];
    strcpy(path, w->file);

    remove_watch(ctx, path);
    add_watch(ctx, path);
}


static void handle_inotify_event(struct notify_service_ctx* ctx, struct notify_watch_entry* watch, struct inotify_event* evt)
{
    if (evt->mask & IN_IGNORED)
    {
        printf("Receieved IN_IGNORED for file \"%s\"; wd=%d; re-applying watch.\n", watch->file, watch->wd);
        update_watch(ctx, watch);
    }

    if (!(evt->mask & IN_CLOSE_WRITE) && !(evt->mask & IN_ATTRIB))
        return;

    fprintf(ctx->log_file, "%s\n", watch->file);
    fflush(ctx->log_file);
}

static void* notify_logic_loop(void* _ctx)
{
    struct notify_service_ctx* ctx = _ctx;

    while (!atomic_load(&ctx->queue_end))
    {
        char event_buffer[sizeof(struct inotify_event) + MAXPATHLEN + 1];

        ssize_t read_bytes = read(ctx->notify_fd, event_buffer, sizeof(event_buffer));

        //Assume on error that fd has closed.
        if (read_bytes < 0)
            break;

        if (read_bytes < sizeof(struct inotify_event))
            continue;

        pthread_mutex_lock(&ctx->watch_lock);

        char* cursor = event_buffer;
        while (read_bytes - (cursor - event_buffer) >= sizeof(struct inotify_event))
        {
            struct inotify_event* event = (struct inotify_event*)cursor;

            if (!event->wd)
                break;

            struct notify_watch_entry* w = find_watch(ctx, event->wd);

            if (w != NULL)
                handle_inotify_event(ctx, w, event);

            cursor += sizeof(struct inotify_event) + event->len;
        }

        pthread_mutex_unlock(&ctx->watch_lock);

    }

    return _ctx;
}

static int add_command(struct notify_service_ctx* ctx, const char* file_name, FILE* command_out)
{
    if (!add_watch(ctx, file_name))
    {
        fprintf(command_out, "Error adding this file to watch list.\n");
        return 0;
    } else
    {
        fprintf(command_out, "File watch added successfully.\n");
        return 1;
    }
}

static int remove_command(struct notify_service_ctx* ctx, const char* file_name, FILE* command_out)
{
    remove_watch(ctx, file_name);
    fprintf(command_out, "File watch was removed.\n");

    return 1;
}

static int status_command(struct notify_service_ctx* ctx, FILE* command_out)
{
    fprintf(command_out, "Notify is active. Log file: %s;\n", ctx->log_file_name);

    return 1;
}

static int list_command(struct notify_service_ctx* ctx, FILE* command_out)
{
    for (int i = 0; i < sizeof(ctx->watches) / sizeof(struct notify_watch_entry); i++)
    {
        if (!ctx->watches[i].file[0])
            continue;;

        fprintf(command_out, "- \"%s\";\n", ctx->watches[i].file);
    }

    fprintf(command_out, "Notify is active. Log file: %s;\n", ctx->log_file_name);

    return 1;
}

static int print_usage(FILE* command_out)
{
    fprintf(command_out, "notify - Monitor & log changes to filesystem files and folders.\n\n");
    fprintf(command_out, "Usage:\n"
        "  notify <verb> [positional arguments]\n\n"
        "  notify help/h/?\n"
        "    Prints this help output\n\n"
        "  notify add <file path>\n"
        "    Add the file at the specified file path to the watch list\n"
        "\n"
        "  notify remove <file path>\n"
        "    Remove the file at the specified path from the watch list.\n"
        "\n"
        "  notify list\n"
        "    List all active file and folder watches.\n"
        "\n"
        "  notify status\n"
        "    Displays the notify service status (whether it is running) and the location of the log file.\n"
        );
    return 0;
}

int process_notify_command(struct notify_service_ctx* ctx, char** argv, int argc, FILE* command_out)
{
    if (argc < 2) {
        fprintf(command_out, "Invalid argument count. Use help command for usage instructions.\n");
        return print_usage(command_out);
    }

    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "?") == 0 || strcmp(argv[1], "h") == 0)
        return print_usage(command_out);

    if (strcmp(argv[1], "add") == 0)
    {
        if (argc < 3)
        {
            fprintf(command_out, "Invalid argument count for add command. Use 'help' for usage instructions.\n");
            return 0;
        }

        return add_command(ctx, argv[2], command_out);
    }

    if (strcmp(argv[1], "remove") == 0)
    {
        if (argc < 3)
        {
            fprintf(command_out, "Invalid argument count for fremove command. Use 'help' for usage instructions.\n");
            return 0;
        }

        return remove_command(ctx, argv[2], command_out);
    }

    if (strcmp(argv[1], "list") == 0)
        return list_command(ctx, command_out);

    if (strcmp(argv[1], "status") == 0)
        return status_command(ctx, command_out);

    fprintf(command_out, "Error, unidentified command: \"%s\"\n", argv[1]);
    print_usage(command_out);

    return 0;
}

static int notify_entry(void* _ctx, char** argv, int argc, FILE* command_out)
{
    struct notify_service_ctx* ctx = _ctx;

    if (strcmp(argv[0], "notify") != 0)
        return 0;

    pthread_mutex_lock(&ctx->watch_lock);
    process_notify_command(ctx, argv, argc, command_out);
    pthread_mutex_unlock(&ctx->watch_lock);

    //We identified the command, so we return 1 (regardless if processing failed or not.)
    return 1;
}

void init_log_file(struct notify_service_ctx* ctx)
{
    strncpy(ctx->log_file_name, "/tmp/notifylogfile_XXXXXX", sizeof(ctx->log_file_name));

    int fd = mkstemp(ctx->log_file_name);

    if (fd < 0)
    {
        fprintf(stderr, "Critical error initialzing the notify service. Could not create logfile fd. Terminating...\n");
        exit(1);
    }

    ctx->log_file = fopen(ctx->log_file_name, "w");
}

void notify_startup(struct cncdaemon_service* dest)
{
    struct notify_service_ctx* ctx = malloc(sizeof(struct notify_service_ctx));

    if (!ctx)
    {
        fprintf(stderr, "Critical error initializing notify service. Could not allocate data.\n");
        exit(1);
    }

    ctx->queue_end = ATOMIC_VAR_INIT(0);
    ctx->notify_fd = inotify_init();

    init_log_file(ctx);

    memset(ctx->watches, 0, sizeof(ctx->watches));

    dest->userdata = ctx;
    dest->handler = notify_entry;

    pthread_mutex_init(&ctx->watch_lock, NULL);
    pthread_create(&ctx->thread, NULL, notify_logic_loop, ctx);
}

void notify_shutdown(struct cncdaemon_service* service)
{
    struct notify_service_ctx* ctx = service->userdata;

    atomic_store(&ctx->queue_end, 1);

    close(ctx->notify_fd);
    pthread_join(ctx->thread, NULL);

    fclose(ctx->log_file);
    free(service);
}