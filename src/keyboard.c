#include "keyboard.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/input.h>
#include <linux/input-event-codes.h>
#include <sys/poll.h>

static const char* key_to_symbol(int key, int shift_status)
{
    switch (key)
    {
        case KEY_ESC: return "<ESC>";
        case KEY_1: return shift_status ? "!" : "1";
        case KEY_2: return shift_status ? "@" : "2";
        case KEY_3: return shift_status ? "#" : "3";
        case KEY_4: return shift_status ? "$" : "4";
        case KEY_5: return shift_status ? "%" : "5";
        case KEY_6: return shift_status ? "^" : "6";
        case KEY_7: return shift_status ? "&" : "7";
        case KEY_8: return shift_status ? "*" : "8";
        case KEY_9: return shift_status ? "(" : "9";
        case KEY_0: return shift_status ? ")" : "0";
        case KEY_MINUS: return shift_status ? "_" :"-";
        case KEY_EQUAL: return shift_status ? "+" :"=";
        case KEY_BACKSPACE: return "<BACKSPACE>";
        case KEY_TAB: return "<TAB>";
        case KEY_Q: return shift_status ? "Q" : "q";
        case KEY_W: return shift_status ? "W" : "w";
        case KEY_E: return shift_status ? "E" : "e";
        case KEY_R: return shift_status ? "R" : "r";
        case KEY_T: return shift_status ? "T" : "t";
        case KEY_Y: return shift_status ? "Y" : "y";
        case KEY_U: return shift_status ? "U" : "u";
        case KEY_I: return shift_status ? "I" : "i";
        case KEY_O: return shift_status ? "O" : "o";
        case KEY_P: return shift_status ? "P" : "p";
        case KEY_LEFTBRACE: return shift_status ? "{" : "[" ;
        case KEY_RIGHTBRACE: return shift_status ? "}" : "]";
        case KEY_ENTER: return "<ENTER>";
        case KEY_LEFTCTRL: return "<CTRL>";
        case KEY_A: return shift_status ? "A" : "a";
        case KEY_S: return shift_status ? "S" : "s";
        case KEY_D: return shift_status ? "D" : "d";
        case KEY_F: return shift_status ? "F" : "f";
        case KEY_G: return shift_status ? "G" : "g";
        case KEY_H: return shift_status ? "H" : "h";
        case KEY_J: return shift_status ? "J" : "j";
        case KEY_K: return shift_status ? "K" : "k";
        case KEY_L: return shift_status ? "L" : "l";
        case KEY_SEMICOLON: return shift_status ? ":" : ";";
        case KEY_APOSTROPHE: return shift_status ? "\"" : "'";
        case KEY_GRAVE: return shift_status ? "~" : "`";
        case KEY_LEFTSHIFT: return "<SHIFT>";
        case KEY_BACKSLASH: return shift_status ? "|" : "\\";
        case KEY_Z: return shift_status ? "Z" : "z";
        case KEY_X: return shift_status ? "X" : "x";
        case KEY_C: return shift_status ? "C" : "c";
        case KEY_V: return shift_status ? "V" : "v";
        case KEY_B: return shift_status ? "B" : "b";
        case KEY_N: return shift_status ? "N" : "n";
        case KEY_M: return shift_status ? "M" : "m";
        case KEY_COMMA: return shift_status ? "<" : ",";
        case KEY_DOT: return shift_status ? ">" : ".";
        case KEY_SLASH: return shift_status ? "?" : "/";
        case KEY_RIGHTSHIFT: return "<SHIFT>";
        case KEY_KPASTERISK: return "*";
        case KEY_LEFTALT: return "<ALT>";
        case KEY_SPACE: return " ";
        case KEY_CAPSLOCK: return "<CAPS-LOCK>";
        case KEY_F1: return "<F1>";
        case KEY_F2: return "<F2>";
        case KEY_F3: return "<F3>";
        case KEY_F4: return "<F4>";
        case KEY_F5: return "<F5>";
        case KEY_F6: return "<F6>";
        case KEY_F7: return "<F7>";
        case KEY_F8: return "<F8>";
        case KEY_F9: return "<F9>";
        case KEY_F10: return "<F10>";
        case KEY_F11: return "<F11>";
        case KEY_F12: return "<F12>";
        case KEY_NUMLOCK: return "<NUMLOCK>";
        case KEY_SCROLLLOCK: return "<SCROLLLOCK";
        case KEY_KPENTER: return "<ENTER>";
        case KEY_RIGHTCTRL: return "<CTRL>";
        case KEY_KPSLASH: return "/";
        case KEY_SYSRQ: return "<SYSRQ>";
        case KEY_RIGHTALT: return "<RIGHTALT";
        case KEY_LINEFEED: return "<LINEFEED>";
        case KEY_HOME: return "<HOME>";
        case KEY_UP: return "<UP>";
        case KEY_PAGEUP: return "<PAGEUP>";
        case KEY_LEFT: return "<LEFT>";
        case KEY_RIGHT: return "<RIGHT>";
        case KEY_END: return "<END>";
        case KEY_DOWN: return "<DOWN>";
        case KEY_PAGEDOWN: return "<PAGEDOWN>";
        case KEY_INSERT: return "<INSERT>";
        case KEY_DELETE: return "<DELETE>";
        default: return "<UNKNOWN>";
    }
}


static int is_capslock_effective(int key)
{
    switch (key)
    {
        case KEY_Q:
        case KEY_W:
        case KEY_E:
        case KEY_R:
        case KEY_T:
        case KEY_Y:
        case KEY_U:
        case KEY_I:
        case KEY_O:
        case KEY_P:
        case KEY_A:
        case KEY_S:
        case KEY_D:
        case KEY_F:
        case KEY_G:
        case KEY_H:
        case KEY_J:
        case KEY_K:
        case KEY_L:
        case KEY_Z:
        case KEY_X:
        case KEY_C:
        case KEY_V:
        case KEY_B:
        case KEY_N:
        case KEY_M:
            return 1;
        default:
            return 0;
    }
}

static int key_is_caps_lock(int key)
{
    return key == KEY_CAPSLOCK;
}

static int key_is_shift(int key)
{
    switch (key)
    {
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
            return 1;
        default:
            return 0;
    }
}

static int test_is_keyboard(unsigned int capabilities_map)
{
    //EV_REP and EV_KEY flags
    const unsigned long target_key_event = 0x100000 | 0x1;
    return (capabilities_map & target_key_event) == target_key_event;
}

static int find_keyboard_event_code()
{
    int found = 0;
    int device = -1;
    unsigned long capabilities_map = 0;

    FILE* devices = fopen("/proc/bus/input/devices", "r");

    if (!devices)
        return -1;

    char* line = NULL;
    size_t len;

    while (getline(&line, &len, devices) != -1)
    {
        if (strncmp(line, "I:", 2) == 0)
        {
            device = -1;
            capabilities_map = 0;
            continue;
        }

        if (strncmp(line, "H:", 2) == 0)
        {
            const char* event_lebel = "event";
            char* event_index = strstr(line, event_lebel);

            if (!event_index)
                continue;

            const char* event_idx_start = event_index + strlen(event_lebel);;
            char* event_idx_end;

            device = (int)strtol(event_idx_start, &event_idx_end, 10);
            if (event_idx_start == event_idx_end)
                device = 0;
        }

        if (strncmp(line, "B:", 2) == 0)
        {
            const char* ev_lebel = "EV=";
            char* evcode = strstr(line, ev_lebel);

            if (!evcode)
                continue;

            const char* evcode_idx_start = evcode + strlen(ev_lebel);;
            char* evcode_idx_end;

            capabilities_map = (int)strtol(evcode_idx_start, &evcode_idx_end, 16);
            if (evcode_idx_start == evcode_idx_end)
                capabilities_map = 0;
        }

        if (device >= 0 && test_is_keyboard(capabilities_map))
        {
            found = 1;
            break;
        }

    }

    free(line);

    fclose(devices);

    return found ? device : -1;
}


int keyboard_open(struct keyboard_session* kb)
{
    char kbname[PATH_MAX];

    int eventcode = find_keyboard_event_code();

    kb->fd = -1;

    if (eventcode < 0)
        return 0;

    sprintf(kbname, "/dev/input/event%d", eventcode);

    int fd = open(kbname, O_RDONLY);

    if (fd < 0)
        return 0;

    kb->fd = fd;
    kb->shift_status = 0;
    kb->capslock_status = 0;

    return 1;
}

int keyboard_close(struct keyboard_session* kb)
{
    if (kb->fd < 0)
        return 0;

    close(kb->fd);
    kb->fd = -1;

    return 1;
}

static void process_key(struct keyboard_session* kb, const struct input_event* input, struct key_event* ke)
{
    ke->is_typed = 0;
    ke->is_complex = 1;
    ke->key_symbol = "<Unidentified>";

    if (input->type != EV_KEY)
        return;

    if (key_is_caps_lock(input->code))
    {
        kb->capslock_status = input->value == 0 != kb->capslock_status;
    } else if (key_is_shift(input->code))
    {
        kb->shift_status = input->value != 0;
    }

    int shift_status = kb->shift_status;

    if (kb->capslock_status && is_capslock_effective(input->code))
        shift_status = !shift_status;

    ke->key_symbol = key_to_symbol(input->code, shift_status);

    ke->is_complex = ke->key_symbol[0] == '<' && ke->key_symbol[1];

    ke->is_typed = 0;

    if(input->value == 2 && ke->is_complex)
        return;

    if(input->value == 0)
        return;

    ke->is_typed = 1;
}

int keyboard_poll(struct keyboard_session* kb, struct key_event* ke)
{
    struct input_event input;

    struct pollfd stdin_poll = {
        .fd = kb->fd,
        .events = POLLIN,
        .revents = 0
    };

    if (poll(&stdin_poll, 1, 0) < 0 || (stdin_poll.revents & POLLIN) == 0)
        return 0;

    ssize_t r = read(kb->fd, &input, sizeof(input));

    if (r != sizeof(input))
        return 0;

    process_key(kb, &input, ke);

    return 1;
}