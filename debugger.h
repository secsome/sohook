#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "elfhelper.h"
#include "vector.h"

struct breakpoint_t
{
    unsigned char original_byte;
    bool enabled;
    size_t address;
    size_t target;
};

struct va_mapping_t
{
    size_t elf_start;
    size_t elf_end;
    void* real_start;
    void* real_end;
};

struct debugger_context
{
    char* executable; // The target executable to be injected
    char* library; // The library to be injected

    pid_t pid;  // The pid of the target process

    struct elf_context elf_exe; // The elf context of the target executable
    struct elf_context elf_lib; // The elf context of the library to be injected 

    // struct va_mapping_t
    struct vector_t va_mappings_exe; // The virtual address mappings of the target process
    struct vector_t va_mappings_lib; // The virtual address mappings of the library to be injected

    size_t entrypoint; // The entrypoint of the target executable

    // struct breakpoint_t
    struct vector_t breakpoints;  // All software breakpoints
    struct breakpoint_t bp_temp; // Temporary breakpoint

    int shmid; // The shared memory id
    void* shmptr; // The shared memory pointer
    void* target_shmptr; // The shared memory pointer in the target process
};

void debugger_init(struct debugger_context* ctx, const char* executable, const char* library);
void debugger_destroy(struct debugger_context* ctx);

void debugger_assert(struct debugger_context* ctx, bool result, const char* format, ...);

void debugger_enable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp);
void debugger_disable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp);

void debugger_continue(struct debugger_context* ctx);
int debugger_wait(struct debugger_context* ctx);
void debugger_run_until(struct debugger_context* ctx, size_t address);

bool debugger_read_memory(struct debugger_context* ctx, size_t address, void* buffer, size_t size);
bool debugger_write_memory(struct debugger_context* ctx, size_t address, const void* buffer, size_t size);

size_t debugger_read_register(struct debugger_context* ctx, size_t reg);
void debugger_write_register(struct debugger_context* ctx, size_t reg, size_t value);