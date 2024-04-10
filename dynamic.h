#pragma once

#include <sys/types.h>

#include "debugger.h"

size_t dynamic_get_target_address(struct debugger_context* ctx, size_t address);

void dynamic_main(struct debugger_context* ctx);
