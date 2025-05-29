#pragma once

#include <stdio.h>

extern const char* CNC_DAEMON_SHELL_INTERFACE_FUNCTION_DEFINITIONS;
extern const char* COMMAND_PIPE_INPUT_ENV_VAR;
extern const char* COMMAND_PIPE_OUTPUT_ENV_VAR;

struct cncdaemon_session_context {
    char command_input_pipe[FILENAME_MAX];
    char command_output_pipe[FILENAME_MAX];
};

typedef void (*cncdaemon_session)(void* userdata, const struct cncdaemon_session_context* session);
typedef int (*cncdaemon_command_handler)(void* userdata, char** argv, int argc, FILE* command_out);

struct cncdaemon_service
{
    cncdaemon_command_handler handler;
    void* userdata;
};

int cncdaemon_start(cncdaemon_session session, void* userdata, struct cncdaemon_service** services);
