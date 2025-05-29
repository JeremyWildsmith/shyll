#pragma once
#include "cncdaemon.h"

void notify_startup(struct cncdaemon_service* dest);
void notify_shutdown(struct cncdaemon_service* service);