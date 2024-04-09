#include "static.h"

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "utils.h"
#include "elfhelper.h"
#include "vector.h"

void static_assert(bool result, const char* format, ...);
void static_create_va_mappings(const char* executable);
void static_advance_to_entrypoint();
size_t static_fva_to_va(size_t fva);

static pid_t target_pid;
static struct elf_context elf = {0};

struct va_mapping_t
{
    size_t elf_start;
    size_t elf_end;
    void* real_start;
    void* real_end;
};
struct vector_t va_mappings;

void static_main(pid_t pid, const char* executable)
{
    // TODO: implement the static hooking
    static_assert(elf_init(&elf, executable), "sohook: failed to open %s\n", executable);

    target_pid = pid;
    static_create_va_mappings(executable);
    static_advance_to_entrypoint();
    utils_dump_pid_maps(pid);

    elf_destroy(&elf);

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // wait the child process to finish
    int status;
    waitpid(pid, &status, 0);
}

void static_assert(bool result, const char* format, ...)
{
    if (!result)
    {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        ptrace(PTRACE_KILL, target_pid, NULL, NULL);
        exit(EXIT_FAILURE);
    }
}

void static_create_va_mappings(const char* executable)
{
    vector_init(&va_mappings, struct va_mapping_t);
    
    // Read /proc/pid/maps to get the memory map of the target process
    char maps_path[PATH_MAX + 1] = {0};
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
    FILE* maps = fopen(maps_path, "r"); 
    static_assert(maps, "sohook: failed to open %s\n", maps_path);

    char realpath_buffer[PATH_MAX + 1] = {0};
    realpath(executable, realpath_buffer);

    char line_buffer[4096] = {0};
    while (fgets(line_buffer, sizeof(line_buffer), maps) != NULL)
    {
        // Not mine
        if (strstr(line_buffer, realpath_buffer) == NULL)
            continue;
        
        // Collect the memory map of the target process
        struct va_mapping_t mapping_item;
        static_assert(sscanf(line_buffer, "%p-%p", &mapping_item.real_start, &mapping_item.real_end) == 2, "sohook: failed to parse memory map\n");
        vector_emplace(&va_mappings, &mapping_item);
    }
    fclose(maps);

    // Read the ELF sections
    size_t loadable_count = 0;
    for (size_t i = 0; i < elf.header.e_phnum; ++i)
    {
        Elf64_Phdr header;
        fseek(elf.file, elf.header.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
        static_assert(fread(&header, sizeof(header), 1, elf.file) == 1, "sohook: failed to read program header\n");

        // Skip non-allocatable sections
        // FIXME: we suppose the order is the same here, which maybe incorrect
        if (header.p_type != PT_LOAD)
            continue;

        ++loadable_count;
        static_assert(loadable_count <= vector_size(&va_mappings), "sohook: too many loadable sections\n");

        struct va_mapping_t* mapping = vector_at(&va_mappings, loadable_count - 1);
        mapping->elf_start = header.p_vaddr;
        mapping->elf_end = header.p_vaddr + header.p_memsz;
    }
}

void static_advance_to_entrypoint()
{
    // Get the entry point of the target process
    size_t entrypoint = static_fva_to_va(elf.header.e_entry);

    size_t instr = ptrace(PTRACE_PEEKDATA, target_pid, entrypoint, NULL);
    static_assert(instr != (size_t)-1, "sohook: failed to read entrypoint original byte\n");

    int ret = ptrace(PTRACE_POKEDATA, target_pid, entrypoint, 0xCC);
    static_assert(ret != -1, "sohook: failed to write entrypoint breakpoint\n");

    ptrace(PTRACE_CONT, target_pid, NULL, NULL);
    int status;
    waitpid(target_pid, &status, 0);

    ret = ptrace(PTRACE_POKEDATA, target_pid, entrypoint, instr);
    static_assert(ret != -1, "sohook: failed to restore entrypoint instruction\n");
}

size_t static_fva_to_va(size_t fva)
{
    for (size_t i = 0; i < vector_size(&va_mappings); ++i)
    {
        struct va_mapping_t* mapping = vector_at(&va_mappings, i);
        if (fva >= mapping->elf_start && fva < mapping->elf_end)
            return (size_t)mapping->real_start + fva - mapping->elf_start;
    }

    static_assert(false, "sohook: failed to convert file va to real va\n");
}