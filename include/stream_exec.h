#pragma once

#include "stream.h"

struct stdin_initialization_step {
    const char* stdin;
    int discard_output;
};

int stream_fork_exec(struct stream_session_context* stream,
    const char* path, char* const args[], const char* const envp[],
    struct stdin_initialization_step* init_steps);

int stream_bind_stdio(struct stream_session_context* stream);