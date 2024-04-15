#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/user.h>

#include "elfhelper.h"
#include "vector.h"

enum
{
    R15, R14, R13, R12,
    RBP, RBX, R11, R10,
    R9, R8, RAX, RCX,
    RDX, RSI, RDI, ORIG_RAX,
    RIP, CS, EFLAGS, RSP,
    SS, FS_BASE, GS_BASE, DS,
    ES, FS, GS,
    REGS_CNT,
};

struct breakpoint_t
{
    size_t address;
    size_t target;
    unsigned char original_byte;
    bool enabled;
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
    bool breakpoints_sorted; // Whether breakpoints are sorted
    struct breakpoint_t bp_temp; // Temporary breakpoint

    void* shellcode_buffer; // The buffer for shellcode
};

void debugger_init(struct debugger_context* ctx, const char* executable, const char* library);
void debugger_destroy(struct debugger_context* ctx);

void debugger_assert(struct debugger_context* ctx, bool result, const char* format, ...);

void debugger_add_breakpoint(struct debugger_context* ctx, size_t address);
struct breakpoint_t* debugger_find_breakpoint(struct debugger_context* ctx, size_t address);
void debugger_enable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp);
void debugger_disable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp);
void debugger_disable_breakpoint_ex(struct debugger_context* ctx, struct breakpoint_t* bp, unsigned char opcode);

int debugger_continue(struct debugger_context* ctx);
int debugger_singlestep(struct debugger_context* ctx);
int debugger_wait(struct debugger_context* ctx);
bool debugger_run_until(struct debugger_context* ctx, size_t address, int* status);

bool debugger_read_memory(struct debugger_context* ctx, size_t address, void* buffer, size_t size);
bool debugger_write_memory(struct debugger_context* ctx, size_t address, const void* buffer, size_t size);

size_t debugger_read_register(struct debugger_context* ctx, size_t reg);
void debugger_write_register(struct debugger_context* ctx, size_t reg, size_t value);
struct user_regs_struct debugger_read_registers(struct debugger_context* ctx);
void debugger_write_registers(struct debugger_context* ctx, const struct user_regs_struct* regs);

size_t debugger_convert_exe_va(struct debugger_context* ctx, size_t va);
size_t debugger_convert_lib_va(struct debugger_context* ctx, size_t va);
size_t debugger_restore_exe_va(struct debugger_context* ctx, size_t va);
size_t debugger_restore_lib_va(struct debugger_context* ctx, size_t va);
void debugger_init_va_mappings(struct debugger_context* ctx, const char* module, struct vector_t* va_mappings, struct elf_context* elf);