#define _GNU_SOURCE

#include "debugger.h"

#include "utils.h"
#include "hookdata.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>

void debugger_init(struct debugger_context* ctx, const char* executable, const char* library)
{
    debugger_destroy(ctx);

    ctx->executable = utils_strdup(executable);
    ctx->library = utils_strdup(library);

    debugger_assert(ctx, elf_init(&ctx->elf_exe, executable), "sohook: failed to parse elf %s\n", executable);
    debugger_assert(ctx, elf_init(&ctx->elf_lib, library), "sohook: failed to parse elf %s\n", library);

    vector_init(&ctx->va_mappings_exe, struct va_mapping_t);
    vector_init(&ctx->va_mappings_lib, struct va_mapping_t);
    vector_init(&ctx->breakpoints, struct breakpoint_t);

    pid_t pid = fork();
    debugger_assert(ctx, pid >= 0, "sohook: failed to fork\n");
    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        char buffer[1024 + 12] = "LD_PRELOAD=";
        strcat(buffer, ctx->library);

        char* const argv[] = {ctx->executable, NULL};
        char* const envp[] = {buffer, NULL};

        execve(ctx->executable, argv, envp);

        debugger_assert(ctx, false, "sohook: failed to execute %s with %s\n", ctx->executable, buffer);
    }
    
    // Wait the child process to be stopped
    debugger_wait(ctx);

    ctx->pid = pid;

    // Initialize the va mappings of the target executable so we can get the entrypoint
    debugger_init_va_mappings(ctx, executable, &ctx->va_mappings_exe, &ctx->elf_exe);

    // Get entrypoint real va and run to the entrypoint
    ctx->entrypoint = debugger_convert_exe_va(ctx, ctx->elf_exe.header.e_entry);
    debugger_run_until(ctx, ctx->entrypoint);

    // Now the library is loaded, initialize its va mappings
    debugger_init_va_mappings(ctx, library, &ctx->va_mappings_lib, &ctx->elf_lib);

    // Now get all the real va of the functions
    hookdata_convert_addresses(&ctx->elf_lib);
    hookdata_verify();

    unsigned char shellcode[] = 
    {
        0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, 0x48, 
        0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 
        0xc6, 0x00, 0x10, 0x00, 0x00, 0x48, 0xc7, 0xc2, 
        0x07, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc2, 0x22, 
        0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0, 0xff, 0xff, 
        0xff, 0xff, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 
        0x00, 0x0f, 0x05, 0xcc,
    };
    unsigned char original_entrypoint[sizeof(shellcode)];
    debugger_assert(ctx, debugger_read_memory(ctx, ctx->entrypoint, original_entrypoint, sizeof(shellcode)), "sohook: failed to read entrypoint\n");

    // Write the shellcode to the entrypoint
    debugger_assert(ctx, debugger_write_memory(ctx, ctx->entrypoint, shellcode, sizeof(shellcode)), "sohook: failed to write entrypoint shellcode\n");

    // Run the shellcode
    debugger_continue(ctx);
    ctx->shellcode_buffer = (void*)debugger_read_register(ctx, RAX);
    
    // Restore the original entrypoint and run it
    debugger_assert(ctx, debugger_write_memory(ctx, ctx->entrypoint, original_entrypoint, sizeof(shellcode)), "sohook: failed to restore entrypoint\n");
    debugger_write_register(ctx, RIP, ctx->entrypoint);

    debugger_run_until(ctx, ctx->entrypoint);
}

void debugger_destroy(struct debugger_context* ctx)
{
    vector_destroy(&ctx->va_mappings_exe);
    vector_destroy(&ctx->va_mappings_lib);
    vector_destroy(&ctx->breakpoints);

    elf_destroy(&ctx->elf_exe);
    elf_destroy(&ctx->elf_lib);

    if (ctx->executable)
    {
        free(ctx->executable);
        ctx->executable = NULL;
    }
    
    if (ctx->library)
    {
        free(ctx->library);
        ctx->library = NULL;
    }
}

void debugger_assert(struct debugger_context* ctx, bool result, const char* format, ...)
{
    if (!result)
    {
        ptrace(PTRACE_KILL, ctx->pid, NULL, NULL);
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(EXIT_FAILURE);
    }
}

void debugger_add_breakpoint(struct debugger_context* ctx, size_t address)
{
    struct breakpoint_t bp = {0};
    bp.address = address;
    vector_emplace(&ctx->breakpoints, &bp);

    ctx->breakpoints_sorted = false;
}

static int debugger_breakpoint_sort_compare(const void* a, const void* b)
{
    const struct breakpoint_t* item_a = (const struct breakpoint_t*)a;
    const struct breakpoint_t* item_b = (const struct breakpoint_t*)b;
    return (item_a->address > item_b->address) - (item_a->address < item_b->address);
}

struct breakpoint_t* debugger_find_breakpoint(struct debugger_context* ctx, size_t address)
{
    const size_t bp_count = vector_size(&ctx->breakpoints);
    if (bp_count == 0)
        return NULL;

    if (!ctx->breakpoints_sorted)
        qsort(ctx->breakpoints.begin, bp_count, sizeof(struct breakpoint_t), debugger_breakpoint_sort_compare);

    struct breakpoint_t bp = {0};
    bp.address = address;
    return (struct breakpoint_t*)bsearch(&bp, ctx->breakpoints.begin, bp_count, sizeof(struct breakpoint_t), debugger_breakpoint_sort_compare);
}

void debugger_enable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp)
{
    if (bp->enabled)
        return;

    debugger_assert(ctx, debugger_read_memory(ctx, bp->address, &bp->original_byte, 1), "sohook: failed to read original byte\n");
    unsigned char int3 = 0xCC;
    debugger_assert(ctx, debugger_write_memory(ctx, bp->address, &int3, 1), "sohook: failed to write breakpoint\n");
    bp->enabled = true;
}

void debugger_disable_breakpoint(struct debugger_context* ctx, struct breakpoint_t* bp)
{
    if (!bp->enabled)
        return;

    debugger_assert(ctx, debugger_write_memory(ctx, bp->address, &bp->original_byte, 1), "sohook: failed to restore original byte\n");
    bp->enabled = false;
}

void debugger_disable_breakpoint_ex(struct debugger_context* ctx, struct breakpoint_t* bp, unsigned char opcode)
{
    if (!bp->enabled)
        return;

    debugger_assert(ctx, debugger_write_memory(ctx, bp->address, &opcode, 1), "sohook: failed to restore to %x\n", opcode);
    bp->enabled = false;
}

int debugger_continue(struct debugger_context* ctx)
{
    ptrace(PTRACE_CONT, ctx->pid, NULL, NULL);
    return debugger_wait(ctx);
}

int debugger_singlestep(struct debugger_context* ctx)
{
    ptrace(PTRACE_SINGLESTEP, ctx->pid, NULL, NULL);
    return debugger_wait(ctx);
}

int debugger_wait(struct debugger_context* ctx)
{
    int status;
    waitpid(ctx->pid, &status, 0);
    return status;
}

void debugger_run_until(struct debugger_context* ctx, size_t address)
{
    ctx->bp_temp.address = address;
    debugger_enable_breakpoint(ctx, &ctx->bp_temp);
    debugger_continue(ctx);
    debugger_disable_breakpoint(ctx, &ctx->bp_temp);
}

bool debugger_read_memory(struct debugger_context* ctx, size_t address, void* buffer, size_t size)
{
    struct iovec local;
    local.iov_base = buffer;
    local.iov_len = size;

    struct iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = size;

    return process_vm_readv(ctx->pid, &local, 1, &remote, 1, 0) != -1;
}

bool debugger_write_memory(struct debugger_context* ctx, size_t address, const void* buffer, size_t size)
{
    // TODO: check if we can modify the tracee's permission to use process_vm_writev on code region.
    // Or we can check the permission first then deciding the approach.

    size_t len = size;
    size_t* buf = (size_t*)buffer;
    for (; len > sizeof(size_t); len -= sizeof(size_t))
    {
        int ret = ptrace(PTRACE_POKEDATA, ctx->pid, (void*)address, *buf++);
        if (ret == -1)
            return false;
        address += sizeof(size_t);
    }

    // Write the remaining bytes
    if (len > 0)
    {
        size_t value = ptrace(PTRACE_PEEKDATA, ctx->pid, (void*)address, NULL);
        if (value == (size_t)-1)
            return false;
        memcpy(&value, buf, len);
        int ret = ptrace(PTRACE_POKEDATA, ctx->pid, (void*)address, value);
        if (ret == -1)
            return false;
    }

    return true;
}

size_t debugger_read_register(struct debugger_context* ctx, size_t reg)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs);
    return *((size_t*)&regs + reg);
}

void debugger_write_register(struct debugger_context* ctx, size_t reg, size_t value)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs);
    *((size_t*)&regs + reg) = value;
    ptrace(PTRACE_SETREGS, ctx->pid, NULL, &regs);
}

struct user_regs_struct debugger_read_registers(struct debugger_context* ctx)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs);
    return regs;
}

void debugger_write_registers(struct debugger_context* ctx, const struct user_regs_struct* regs)
{
    ptrace(PTRACE_SETREGS, ctx->pid, NULL, regs);
}

size_t debugger_convert_exe_va(struct debugger_context* ctx, size_t va)
{
    for (size_t i = 0; i < vector_size(&ctx->va_mappings_exe); ++i)
    {
        struct va_mapping_t* mapping = vector_at(&ctx->va_mappings_exe, i);
        if (va >= mapping->elf_start && va < mapping->elf_end)
            return (size_t)mapping->real_start + va - mapping->elf_start;
    }

    debugger_assert(ctx, false, "sohook: failed to convert exe va %p\n", va);
    return 0;
}

size_t debugger_convert_lib_va(struct debugger_context* ctx, size_t va)
{
    for (size_t i = 0; i < vector_size(&ctx->va_mappings_lib); ++i)
    {
        struct va_mapping_t* mapping = vector_at(&ctx->va_mappings_lib, i);
        if (va >= mapping->elf_start && va < mapping->elf_end)
            return (size_t)mapping->real_start + va - mapping->elf_start;
    }

    debugger_assert(ctx, false, "sohook: failed to convert lib va %p\n", va);
    return 0;
}

size_t debugger_restore_exe_va(struct debugger_context* ctx, size_t va)
{
    for (size_t i = 0; i < vector_size(&ctx->va_mappings_exe); ++i)
    {
        struct va_mapping_t* mapping = vector_at(&ctx->va_mappings_exe, i);
        if (va >= (size_t)mapping->real_start && va < (size_t)mapping->real_end)
            return mapping->elf_start + va - (size_t)mapping->real_start;
    }

    debugger_assert(ctx, false, "sohook: failed to restore exe va %p\n", va);
    return 0;
}

size_t debugger_restore_lib_va(struct debugger_context* ctx, size_t va)
{
    for (size_t i = 0; i < vector_size(&ctx->va_mappings_lib); ++i)
    {
        struct va_mapping_t* mapping = vector_at(&ctx->va_mappings_lib, i);
        if (va >= (size_t)mapping->real_start && va < (size_t)mapping->real_end)
            return mapping->elf_start + va - (size_t)mapping->real_start;
    }

    debugger_assert(ctx, false, "sohook: failed to restore lib va %p\n", va);
    return 0;
}

void debugger_init_va_mappings(struct debugger_context* ctx, const char* module, struct vector_t* va_mappings, struct elf_context* elf)
{
    char maps_path[PATH_MAX + 1] = {0};
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", ctx->pid);
    FILE* maps = fopen(maps_path, "r"); 
    debugger_assert(ctx, maps, "sohook: failed to open %s\n", maps_path);

    char* realpath_ptr = realpath(module, NULL);
    char line_buffer[4096] = {0};
    while (fgets(line_buffer, sizeof(line_buffer), maps) != NULL)
    {
        // Not mine
        if (strstr(line_buffer, realpath_ptr) == NULL)
            continue;
        
        // Collect the memory map of the target process
        struct va_mapping_t mapping_item;
        debugger_assert(ctx, sscanf(line_buffer, "%p-%p", &mapping_item.real_start, &mapping_item.real_end) == 2, "sohook: failed to parse memory map\n");
        vector_emplace(va_mappings, &mapping_item);
    }
    fclose(maps);
    free(realpath_ptr);

    // Read the ELF sections
    size_t loadable_count = 0;
    for (size_t i = 0; i < elf->header.e_phnum; ++i)
    {
        Elf64_Phdr header;
        fseek(elf->file, elf->header.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
        debugger_assert(ctx, fread(&header, sizeof(header), 1, elf->file) == 1, "sohook: failed to read program header\n");

        // Skip non-loadable sections
        // FIXME: we suppose the order is the same here, which maybe incorrect
        if (header.p_type != PT_LOAD)
            continue;

        ++loadable_count;
        debugger_assert(ctx, loadable_count <= vector_size(va_mappings), "sohook: too many loadable sections\n");

        struct va_mapping_t* mapping = vector_at(va_mappings, loadable_count - 1);
        mapping->elf_start = header.p_vaddr;
        mapping->elf_end = header.p_vaddr + header.p_memsz;
    }
}

