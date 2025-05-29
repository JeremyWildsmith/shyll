#pragma once

#include <stdio.h>
#include "handshake.h"

struct stream_session_context;

typedef void (*stream_session)(void* userdata, struct stream_session_context* session);

void stream_start(const struct encrypt_auth* auth, const struct handshake_established* established, stream_session session, int disable_heartbeat, void* userdata);

int stream_is_alive(struct stream_session_context* ctx);
ssize_t stream_read(struct stream_session_context* ctx, char* buffer, const size_t buffer_sz);
ssize_t stream_write(struct stream_session_context* ctx, const char* buffer, const size_t buffer_sz);
int stream_poll_cmd(struct stream_session_context* ctx, unsigned short* cmd);

void stream_close(struct stream_session_context* ctx);
void stream_command(struct stream_session_context* ctx, unsigned char command);