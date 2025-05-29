#include "stream_exec.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pty.h>
#include <poll.h>
#include <time.h>

#include <stdatomic.h>
#include <stdbool.h>

#include "stream.h"
#include "stream_id.h"
#include "util.h"

static int STREAM_FORWARD_SLEEP_INTERVAL = 10;
static unsigned int STREAM_BUFFER_SZ = 4096;
static int DISCARD_CATCHMENT_INTERVAL = 3;

static struct stream_session_context* active_stdio_exec_bind = 0;

static int is_alive(pid_t child) {
    int status;

    if (child == getpid())
        return 1;

    int result = waitpid(child, &status, WNOHANG);

    //On error, assume process is dead.
    if (result < 0)
        return 0;

    if (result == 0)
        return 1;

    //In this case, we know process state has changed (PID > 0)
    return !(WIFEXITED(status) || WIFSIGNALED(status));
}

static int write_fifo_into_stream(int fifo_stdin, struct stream_session_context* stream) {
    char buffer[STREAM_BUFFER_SZ];

    struct pollfd stdin_poll = {
        .fd = fifo_stdin,
        .events = POLLIN,
        .revents = 0
    };

    if (poll(&stdin_poll, 1, 0) < 0 || (stdin_poll.revents & POLLIN) == 0)
        return 1;

    ssize_t read_data = read(fifo_stdin, buffer, sizeof(buffer));

    if (read_data < 0) {
        return 0;
    }

    if (read_data == 0)
        return 1;

    //We can safely assume stream_write will write the entire buffer (implementation detail.)
    stream_write(stream, buffer, read_data);
    return 1;
}

static void discard_fd_data(int fd, int max_delay) {
    char buffer[4096];

    unsigned int last_discard = time(NULL);
    do {
        struct pollfd stdin_poll = {
            .fd = fd,
            .events = POLLIN,
            .revents = 0
        };

        if (poll(&stdin_poll, 1, STREAM_FORWARD_SLEEP_INTERVAL) < 0 || (stdin_poll.revents & POLLIN) == 0)
            continue;

        ssize_t r = read(fd, buffer, sizeof(buffer));

        if (r < 0 && errno != EAGAIN)
            return;

        if (r > 0)
            last_discard = time(NULL);
    } while (time(NULL) - last_discard < max_delay);
}

static int flush_into_fd(int fd, const char* data, int discard_results) {
    size_t data_size = strlen(data);

    if (data_size == 0)
        return 0;

    ssize_t data_written = 0;

    while (data_written < data_size) {
        ssize_t progress = write(fd, &data[data_written], data_size - data_written);

        if (discard_results)
            discard_fd_data(fd, 0);

        if (progress < 0)
            return 0;

        data_written += progress;
    }

    return 1;
}

static void drive_stdio(struct stream_session_context* stream, pid_t child, pid_t session_group, int fd_write_stream_to, int fd_read_into_stream) {
    char write_buffer[STREAM_BUFFER_SZ];
    unsigned short cmd_buffer;
    ssize_t data_size = 0;
    ssize_t data_written = 0;

    while (is_alive(child) && stream_is_alive(stream)) {
        yield_proc();

        if (stream_poll_cmd(stream, &cmd_buffer) && cmd_buffer == STREAM_COMMAND_SIGINT)
        {
            if (session_group && session_group != -1)
            {
                printf("Sending sigint...\n");
                kill(-session_group, SIGINT);
            }
        }

        if (data_written >= data_size) {
            data_size = stream_read(stream, write_buffer, sizeof(write_buffer));

            data_written = 0;

            if (data_size < 0) {
                fprintf(stderr, "Error reading from stream. Termining stdio driver.");
                break;
            }
        }

        if (data_written < data_size) {
            char* cursor = &write_buffer[data_written];

            ssize_t progress = write(fd_write_stream_to, cursor, data_size - data_written);

            if (progress < 0) {
                fprintf(stderr, "Error writing to stdin fifo, terminating.\n");
                break;
            }

            data_written += progress;
        }

        if (!write_fifo_into_stream(fd_read_into_stream, stream)) {
            fprintf(stderr, "Error reading from stdout fifo into stream. Terminating...\n");
            break;
        }
    }

    close(fd_read_into_stream);
    close(fd_write_stream_to);
}

static void exec_with_stdio(int fifo_stdin, int fifo_stdout, const char* path, char* const args[], const char* const envp[]) {
    if (dup2(fifo_stdin, STDIN_FILENO) == -1) {
        fprintf(stderr, "Failed to redirect fifo_stdin to stdin.\n");
        exit(1);
    }

    if (dup2(fifo_stdout, STDOUT_FILENO) == -1 || dup2(fifo_stdout, STDERR_FILENO) == -1) {
        fprintf(stderr, "Failed to redirect fifo_stdout to stdout.\n");
        exit(1);
    }

    //This cast is safe. execve never writes back to envp...
    execve(path, args, (char * const *)envp);

    //If we get here, execv failed
    fprintf(stderr, "Failed to invoke exec.\n");
    exit(1);
}

static void initialize_stdin(int stdin_fd, struct stdin_initialization_step* init_steps) {
    for (struct stdin_initialization_step* cursor = init_steps; cursor->stdin; cursor++) {
        flush_into_fd(stdin_fd, cursor->stdin, cursor->discard_output);

        if (cursor->discard_output) {
            discard_fd_data(stdin_fd, DISCARD_CATCHMENT_INTERVAL);
        }
    }
}

int stream_fork_exec(struct stream_session_context* stream, const char* path, char* const args[], const char* const envp[], struct stdin_initialization_step* init_steps) {
    int fd_master, fd_slave;

    if (openpty(&fd_master, &fd_slave, NULL, NULL, NULL) == -1) {
        fprintf(stderr, "Error opening pseudo terminal.\n");
        return -1;
    }

    pid_t pid = fork();

    if (pid == -1)
        return -1;

    if (pid) {
        if (init_steps) {
            initialize_stdin(fd_master, init_steps);
        }

        pid_t grp = getpgid(pid);

        const char* ready_message = "Interactive session is ready!\n";
        flush_into_fd(fd_slave, ready_message, 0);
        printf("stdin inited. Executing...\n");
        drive_stdio(stream, pid, grp, fd_master, fd_master);
        return 0;
    } else {
        setsid();
        exec_with_stdio(fd_slave, fd_slave, path, args, envp);
        return 0;
    }
}

static void configure_stdin_no_buffering() {
    struct termios config;

    if (tcgetattr(STDIN_FILENO, &config) == -1)
        return;

    //Disable canonical mode, which buffers between newlines
    config.c_lflag &= ~ICANON;

    //We don't want to echo the characters we type back in to stdout, since the remote
    //terminal will do this for us.
    config.c_lflag &= ~ECHO;

    //http://www.unixwiz.net/techtips/termios-vmin-vtime.html
    //Send the console data as soon as it is available from the user.
    config.c_cc[VMIN] = 1;
    config.c_cc[VTIME] = 0;

    //Don't care if this fails. This function tries to enter direct i/o mode, but it isn't critical
    //we do enter it.
    tcsetattr(STDIN_FILENO, TCSANOW, &config);
}

static void stream_bind_interrupt_handler(int _sig)
{
    if (!active_stdio_exec_bind || !stream_is_alive(active_stdio_exec_bind))
    {
        fprintf(stderr, "Remote end does not appear alive. Terminating...");
        exit(1);
    }

    stream_command(active_stdio_exec_bind, STREAM_COMMAND_SIGINT);
}

int stream_bind_stdio(struct stream_session_context* stream) {
    configure_stdin_no_buffering();

    active_stdio_exec_bind = stream;

    signal(SIGINT, stream_bind_interrupt_handler);

    drive_stdio(stream, getpid(), 0, STDOUT_FILENO, STDIN_FILENO);

    active_stdio_exec_bind = 0;
    return 0;
}