#include "elfhelper.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

static void elf_read_section_string(struct elf_context* ctx, char* buffer, Elf64_Word off)
{
    long current_off = ftell(ctx->file);
    fseek(ctx->file, ctx->sh_shstrtab_header.sh_offset + off, SEEK_SET);
    utils_assert(fscanf(ctx->file, "%255s", buffer) > 0, "sohook: Failed to read section string\n");
    fseek(ctx->file, current_off, SEEK_SET);
}

static void elf_read_string(struct elf_context* ctx, char* buffer, Elf64_Word off)
{
    long current_off = ftell(ctx->file);
    fseek(ctx->file, ctx->sh_strtab_header.sh_offset + off, SEEK_SET);
    utils_assert(fscanf(ctx->file, "%255s", buffer) > 0, "sohook: Failed to read string\n");
    fseek(ctx->file, current_off, SEEK_SET);
}

static bool elf_read_section(struct elf_context* ctx, const char* name, Elf64_Shdr* section)
{
    fseek(ctx->file, ctx->header.e_shoff, SEEK_SET);
    for (Elf64_Half i = 0; i < ctx->header.e_shnum; ++i)
    {
        if (fread(section, sizeof(Elf64_Shdr), 1, ctx->file) != 1)
            return false;
        
        char section_name[0x100] = { 0 };
        elf_read_section_string(ctx, section_name, section->sh_name);
        if (!strcmp(section_name, name))
            return true;
    }
    return false;
}

bool elf_init(struct elf_context* ctx, const char* filename)
{
    elf_destroy(ctx);

    ctx->file = fopen(filename, "rb");
    ctx->section_va = NULL;

    if (fread(&ctx->header, sizeof(ctx->header), 1, ctx->file) != 1)
    {
        fprintf(stderr, "sohook: Failed to read ELF header\n");
        return false;
    }

    if (memcmp(ctx->header.e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "sohook: Invalid ELF header\n");
        return false;
    }

    // Get section string table
    fseek(ctx->file, ctx->header.e_shoff + ctx->header.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    if (fread(&ctx->sh_shstrtab_header, sizeof(ctx->sh_shstrtab_header), 1, ctx->file) != 1)
    {
        fprintf(stderr, "sohook: Failed to read section header string table\n");
        return false;
    }

    // Get necessary sections
    elf_read_section(ctx, ".symtab", &ctx->sh_symtab_header);
    elf_read_section(ctx, ".strtab", &ctx->sh_strtab_header);

    // Fill section VA info
    fseek(ctx->file, ctx->header.e_shoff, SEEK_SET);
    ctx->section_va = utils_malloc(ctx->header.e_shnum * sizeof(struct elf_context_vainfo));
    for (size_t i = 0; i < ctx->header.e_shnum; ++i)
    {
        Elf64_Shdr section;
        if (fread(&section, sizeof(section), 1, ctx->file) != 1)
        {
            fprintf(stderr, "sohook: Failed to read section header\n");
            return false;
        }

        ctx->section_va[i].sh_addr = section.sh_addr;
        ctx->section_va[i].sh_offset = section.sh_offset;
        ctx->section_va[i].sh_size = section.sh_size;
    }

    return true;
}

void elf_destroy(struct elf_context* ctx)
{
    if (ctx->file != NULL)
    {
        fclose(ctx->file);
        ctx->file = NULL;
    }
    if (ctx->section_va != NULL)
    {
        free(ctx->section_va);
        ctx->section_va = NULL;
    }
}

bool elf_read_va_string(struct elf_context* ctx, Elf64_Addr va, char* buffer)
{
    // Convert va into file offset
    for (size_t i = 0; i < ctx->header.e_shnum; ++i)
    {
        if (va >= ctx->section_va[i].sh_addr && va < ctx->section_va[i].sh_addr + ctx->section_va[i].sh_size)
        {
            // In this section, read the string
            fseek(ctx->file, va - ctx->section_va[i].sh_addr + ctx->section_va[i].sh_offset, SEEK_SET);
            utils_assert(fscanf(ctx->file, "%255s", buffer) > 0, "sohook: Failed to read va string\n");
            return true;
        }
    }

    return false;
}

struct elf_section_data elf_read_section_data(struct elf_context* ctx, const char* section_name)
{
    struct elf_section_data result = { NULL, 0 };

    Elf64_Shdr section;
    if (!elf_read_section(ctx, section_name, &section))
    {
        fprintf(stderr, "sohook: Failed to find section %s\n", section_name);
        return result;
    }

    void* data = utils_malloc(section.sh_size);
    fseek(ctx->file, section.sh_offset, SEEK_SET);
    if (fread(data, section.sh_size, 1, ctx->file) != 1)
    {
        fprintf(stderr, "sohook: Failed to read section %s\n", section_name);
        free(data);
        return result;
    }

    result.data = data;
    result.size = section.sh_size;

    return result;
}

void elf_read_section_name(struct elf_context* ctx, Elf64_Addr offset, char* buffer)
{
    elf_read_section_string(ctx, buffer, offset);
}

void elf_read_symbol_string(struct elf_context* ctx, Elf64_Word off, char* buffer)
{
    elf_read_string(ctx, buffer, off);
}