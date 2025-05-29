#include "cncdaemon.h"
#include "cncdaemon_data.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bits/fcntl-linux.h>
#include <bits/pthreadtypes.h>
#include <sys/stat.h>

const char* CNC_DAEMON_SHELL_INTERFACE_FUNCTION_DEFINITIONS = CNC_DAEMON_BASH_INIT;
const char* COMMAND_PIPE_INPUT_ENV_VAR = "cnc_cmd_input";
const char* COMMAND_PIPE_OUTPUT_ENV_VAR = "cnc_cmd_output";

struct cncdaemon_daemon_ctx {
    struct cncdaemon_session_context* session;
    volatile int* queue_end;
    int input_command_fd;
    struct cncdaemon_service** services;
};

char** allocate_argv(char* buffer, int* argc) {
    *argc = 0;
    char was_space = 1;
    for (char* c = buffer + 1; *c; c++) {
        if (isspace(*c)) {
            *c = 0;

            was_space = 1;
        } else {
            if (was_space)
                (*argc)++;

            was_space = 0;
        }
    }

    if (*argc == 0)
        return 0;

    char** argv = malloc(sizeof(char*) * *argc);

    if (!argv) {
        fprintf(stderr, "Unable to allocate argv list for command.\n");
        return 0;
    }

    char* cursor = buffer;
    for (unsigned int i = 0; i < *argc; i++) {
        while (!*cursor)
            cursor++;

        argv[i] = cursor;

        while (*cursor)
            cursor++;
    }

    return argv;
}

void execute_command(struct cncdaemon_service** services, char** argv, int argc, FILE* command_out) {
    if (!services || argc == 0)
        return;

    int resolved = 0;
    for (struct cncdaemon_service** c = services; *c; c++)
    {
        if ((*c)->handler((*c)->userdata, argv, argc, command_out))
        {
            resolved = 1;
            break;
        }
    }

    if (!resolved)
    {
        fprintf(command_out, "Command \"%s\" is not an identified command.\n", argv[0]);
    }
}

void process_command(struct cncdaemon_service** services, const char* cmd_out_pipe, char* cmd_buffer) {
    //Trim spaces
    while (*cmd_buffer != 0 && isspace(*cmd_buffer))
        cmd_buffer++;

    int argc;
    char** argv = allocate_argv(cmd_buffer, &argc);

    if (argv == NULL)
        return;

    if (argc != 0) {
        printf("Waiting for pipe to open...\n");
        FILE* output_pipe = fopen(cmd_out_pipe, "w");

        printf("Pipe opened!\n");
        if (!output_pipe) {
            fprintf(stderr, "Error opening output pipe. Using host stdout instead (this is probably not desired effect.)\n");
            output_pipe = stdout;
        }

        execute_command(services, argv, argc, output_pipe);

        if (output_pipe != stdout)
            fclose(output_pipe);
    }

    free(argv);
}

int consume_and_shift(struct cncdaemon_service** services, const char* cmd_out_pipe, char* buffer, const size_t sz) {
    char* cmd_end = strchr(buffer, '\n');

    if (!cmd_end)
        return 0;

    *cmd_end = 0;

    process_command(services, cmd_out_pipe, buffer);

    //Shift the buffer over...
    char intermediate_buffer[sz];
    strcpy(intermediate_buffer, cmd_end + 1);
    strcpy(buffer, intermediate_buffer);

    return 1;
}

void* command_recv_thread(void* _ctx) {
    struct cncdaemon_daemon_ctx* ctx = _ctx;

    char command_line_buffer[FILENAME_MAX * 4];
    size_t buffer_sz = 0;
    while (!*ctx->queue_end) {
        if (consume_and_shift(ctx->services, ctx->session->command_output_pipe, command_line_buffer, sizeof(command_line_buffer))) {
            //if we consumed and shifted, recalculate the size
            buffer_sz = strlen(command_line_buffer);
        }

        const ssize_t read_limit = (ssize_t)(sizeof(command_line_buffer) - buffer_sz - 1);

        //If we can't read anything, and no command was pulled off, then the command loop will get stuck. We wipe it
        //and start over.
        if (read_limit <= 0) {
            fprintf(stderr, "Error, command buffer filled, but was not able to pull any complete commands. Flushing buffer.\n");
            command_line_buffer[0] = 0;
            buffer_sz = 0;
            continue;
        }

        //Read in a max of buffer size less one byte, we want to ensure the null terminator is added after reading
        //since we assume we only ever get strings written to this pipe.
        ssize_t data_consumed = read(ctx->input_command_fd, command_line_buffer + buffer_sz, read_limit);

        if (data_consumed < 0 && errno != EAGAIN) {
            fprintf(stderr, "Error reading from input (stderr=%d). Terminating.\n", errno);
            break;
        }

        if (data_consumed > 0) {
            buffer_sz += data_consumed;
            command_line_buffer[buffer_sz] = 0;
        } else
        {
            sleep(1);
        }
    }

    *ctx->queue_end = 1;

    return _ctx;
}

static int mktempfifo(char* name_buffer, size_t name_sz, mode_t mode) {
    const char* name_pattern = "/tmp/cncdaemon_XXXXXX";

    if (name_sz < strlen(name_buffer))
        return -1;

    strcpy(name_buffer, name_pattern);

    int file_fd = mkstemp(name_buffer);

    if (file_fd < 0)
        return -1;

    close(file_fd);
    remove(name_buffer);

    return mkfifo(name_buffer, mode);
}

int create_and_open_command_pipe(struct cncdaemon_daemon_ctx* ctx) {
    if (mktempfifo(ctx->session->command_input_pipe, sizeof(ctx->session->command_input_pipe), S_IRWXU | S_IRWXO | S_IRWXG) != 0) {
        fprintf(stderr, "Error, unable to start the cncdaemon... Could not create the INPUT pipe: %s\n", ctx->session->command_input_pipe);
        return 0;
    }

    if (mktempfifo(ctx->session->command_output_pipe, sizeof(ctx->session->command_output_pipe), S_IRWXU | S_IRWXO | S_IRWXG) != 0) {
        fprintf(stderr, "Error, unable to start the cncdaemon... Could not create the OUTPUT pipe: %s\n", ctx->session->command_input_pipe);
        return 0;
    }

    int in_pipe_fd = open(ctx->session->command_input_pipe, O_RDONLY | O_NONBLOCK);

    if (in_pipe_fd < 0)
        return 0;

    ctx->input_command_fd = in_pipe_fd;

    return 1;
}

int cncdaemon_start(cncdaemon_session session, void* userdata, struct cncdaemon_service** services) {
    volatile int  queue_end = 0;
    pthread_t recv_thread;

    struct cncdaemon_session_context ctx = {0};

    struct cncdaemon_daemon_ctx daemon_ctx = {
        .session = &ctx,
        .queue_end = &queue_end,
        .services = services
    };

    if (!create_and_open_command_pipe(&daemon_ctx)) {
        fprintf(stderr, "Error, unable to start the cncdaemon... Could not create / open the pipe: %s\n", ctx.command_input_pipe);
        return 0;
    }

    pthread_create(&recv_thread, NULL, command_recv_thread, &daemon_ctx);

    session(userdata, &ctx);

    queue_end = 1;
    pthread_join(recv_thread, NULL);
    close(daemon_ctx.input_command_fd);

    return 1;
}
