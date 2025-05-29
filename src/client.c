#include "client.h"

#include <unistd.h>

#include "knocking.h"
#include "stream_exec.h"

void logic_client(void* _args, struct stream_session_context* session) {
    stream_bind_stdio(session);
}

int run_client(struct client_arguments* arguments) {
    printf("Attempting to establish connection...\n");

    struct handshake_established connection;
    struct encrypt_auth auth;

    encrypt_init(arguments->password, &auth);

    if (!handshake_connect(&auth, arguments->remote_ip, 10, &connection)) {
        fprintf(stderr, "Error connecting to remote \"%s\", no response. Incorrect password? Terminating.\n", arguments->remote_ip);
        return 1;
    }

    printf("Connection established, please wait for remote to initialize...\n");
    stream_start(&auth, &connection, logic_client, !arguments->heartbeat, arguments);

    return 0;
}

int do_knock(const char* remote, const char* password) {
    struct encrypt_auth auth;

    encrypt_init(password, &auth);

    for (int i = 0; i < 4; i++)
    {
        printf("Sending knock sequence %d/%d\n", i + 1, 4);
        knock_send(&auth, remote);
        sleep(2);
    }

    puts("Done\n");

    return 0;
}