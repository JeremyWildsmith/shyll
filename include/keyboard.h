#pragma once
#include <stddef.h>

struct keyboard_session
{
    int fd;
    int shift_status;
    int capslock_status;
};

struct key_event
{
    const char* key_symbol;
    int is_complex;
    int is_typed;
};

int keyboard_open(struct keyboard_session* kb);
int keyboard_close(struct keyboard_session* kb);
int keyboard_poll(struct keyboard_session* kb, struct key_event* ke);

