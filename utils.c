#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void utils_assert(bool result, const char* format, ...)
{
    if (!result)
    {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(EXIT_FAILURE);
    }
}

bool utils_check_file_available(const char* filepath)
{
    FILE* file = fopen(filepath, "r");
    if (file)
    {
        fclose(file);
        return true;
    }
    return false;
}

void* utils_malloc(size_t size)
{
    void* ptr = malloc(size);
    utils_assert(ptr != NULL, "sohook: Failed to allocate memory\n");
    return ptr;
}

void* utils_realloc(void* ptr, size_t size)
{
    void* new_ptr = realloc(ptr, size);
    utils_assert(new_ptr != NULL, "sohook: Failed to reallocate memory\n");
    return new_ptr;
}

char* utils_strdup(const char* str)
{
    char* new_str = utils_malloc(strlen(str) + 1);
    strcpy(new_str, str);
    return new_str;
}

void utils_dump_pid_maps(pid_t pid)
{
    char maps_filepath[64];
    sprintf(maps_filepath, "/proc/%d/maps", pid);

    FILE* maps_file = fopen(maps_filepath, "r");
    if (!maps_file)
    {
        fprintf(stderr, "sohook: Failed to open %s\n", maps_filepath);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file))
        printf("%s", line);

    fclose(maps_file);
}