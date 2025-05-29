#pragma once
#include "icmp_encrypt.h"
#include "cncdaemon.h"

void nftables_control_startup(struct encrypt_auth* auth, unsigned int knock_window_length_s, struct cncdaemon_service* dest);
void nftables_control_shutdown(struct cncdaemon_service* service);