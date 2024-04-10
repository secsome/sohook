#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <elf.h>

struct elf_context_vainfo
{
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
};

struct elf_context
{
    FILE* file;
    Elf64_Ehdr header;
    Elf64_Shdr sh_shstrtab_header;
    Elf64_Shdr sh_symtab_header;
    Elf64_Shdr sh_strtab_header;
    struct elf_context_vainfo* section_va;
};

struct elf_section_data
{
    void* data;
    size_t size;
};

bool elf_init(struct elf_context* ctx, const char* filename);
void elf_destroy(struct elf_context* ctx);
bool elf_read_va_string(struct elf_context* ctx, Elf64_Addr va, char* buffer);
struct elf_section_data elf_read_section_data(struct elf_context* ctx, const char* section_name);
void elf_read_section_name(struct elf_context* ctx, Elf64_Addr offset, char* buffer);
void elf_read_symbol_string(struct elf_context* ctx, Elf64_Word off, char* buffer);