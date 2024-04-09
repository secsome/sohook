#pragma once

#include <stdbool.h>
#include <stddef.h>

// Print the error message if result is false and exit the program.
void utils_assert(bool result, const char* format, ...);

bool utils_check_file_available(const char* filepath);

void* utils_malloc(size_t size);
void* utils_realloc(void* ptr, size_t size);
char* utils_strdup(const char* str);