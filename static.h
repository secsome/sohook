#pragma once

#include <stdbool.h>
#include <sys/types.h>

void static_assert(bool result, const char* format, ...);

void static_main(pid_t pid, const char* executable);