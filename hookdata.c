#include "hookdata.h"
#include "elfhelper.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t hookdata_count;
static size_t hookdata_capacity;
struct hookdata* hookdata_list;
static bool hookdata_sorted;

static int hookdata_sort_compare(const void* a, const void* b)
{
    const struct hookdata* item_a = (const struct hookdata*)a;
    const struct hookdata* item_b = (const struct hookdata*)b;
    return (item_a->address > item_b->address) - (item_a->address < item_b->address);
}

void hookdata_verify()
{
    utils_assert(hookdata_list, "sohook: Hook data list is not initialized\n");
    utils_assert(hookdata_count > 0, "sohook: Hook data list is empty\n");
    
    if (!hookdata_sorted)
        qsort(hookdata_list, hookdata_count, sizeof(struct hookdata), hookdata_sort_compare);

    for (size_t i = 1; i < hookdata_count; ++i)
        utils_assert(hookdata_list[i - 1].address != hookdata_list[i].address, "sohook: Duplicate hook data address\n");
    
    for (size_t i = 0; i < hookdata_count; ++i)
        utils_assert(hookdata_list[i].function_address != (size_t)-1, "sohook: Function address for %s is not resolved\n", hookdata_list[i].function);
}

void hookdata_clear()
{
    if (hookdata_list)
    {
        for (size_t i = 0; i < hookdata_count; ++i)
        {
            if (hookdata_list[i].function)
            {
                free(hookdata_list[i].function);
                hookdata_list[i].function = NULL;
            }
        }
        free(hookdata_list);
        hookdata_list = NULL;
    }
    hookdata_count = 0;
    hookdata_capacity = 0;
}

void hookdata_add(void* address, const char* function, size_t length)
{
    if (hookdata_count == hookdata_capacity)
    {
        hookdata_capacity += 0x100;
        hookdata_list = utils_realloc(hookdata_list, hookdata_capacity * sizeof(struct hookdata));
    }

    hookdata_list[hookdata_count].address = address;
    hookdata_list[hookdata_count].length = length;
    hookdata_list[hookdata_count].function = utils_strdup(function);
    hookdata_list[hookdata_count].function_address = (size_t)-1;
    ++hookdata_count;

    hookdata_sorted = false;
}

struct hookdata* hookdata_find(void* address)
{
    if (hookdata_list == NULL || hookdata_count == 0)
        return NULL;

    if (!hookdata_sorted)
        qsort(hookdata_list, hookdata_count, sizeof(struct hookdata), hookdata_sort_compare);

    struct hookdata hd = {0};
    hd.address = address;
    return bsearch(&hd, hookdata_list, hookdata_count, sizeof(struct hookdata), hookdata_sort_compare);
}

void hookdata_load_inj(const char *filename)
{
    // TARGET = FUNCTION, LENGTH
    // e.g: 405864 = HACK_PRINTF_1, 5
    
    hookdata_clear();
    
    FILE* file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "sohook: Failed to open hook data file %s\n", filename);
        return;
    }

    // For each line of the buffer, it should be no longer than 1024 characters.
    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Skip comments and empty lines.
        if (*line == ';' || *line == '\r' || *line == '\n')
            continue;
        
        char function[1024];
        function[0] = 0;
        void *address = NULL;
        size_t length = 0;

        // parse the line(length is optional, defaults to 0)
        if (sscanf(line, "%p = %[^ \t;,\r\n] , %zx", &address, function, &length) >= 2)
            hookdata_add(address, function, length);
    }

    fclose(file);
}

void hookdata_load_elf(const char *filename)
{
    hookdata_clear();
    
    struct elf_context elf = {0};
    utils_assert(elf_init(&elf, filename), "sohook: Failed to initialize ELF context\n");

    // Get section .sohook
    struct elf_section_data data = elf_read_section_data(&elf, ".sohook");
    utils_assert(data.size > 0 && data.size % sizeof(struct hookdecl_t) == 0, "sohook: Invalid .sohook section\n");

    size_t item_count = data.size / sizeof(struct hookdecl_t);
    for (size_t i = 0; i < item_count; ++i)
    {
        const struct hookdecl_t* item = (struct hookdecl_t*)data.data + i;
        void* address = item->address;
        size_t length = item->length;
        char function[1024];
        utils_assert(elf_read_va_string(&elf, (Elf64_Addr)item->function, function), "sohook: Failed to read function name\n");
        hookdata_add(address, function, length);
    }

    elf_destroy(&elf);
}

void hookdata_convert_address(struct hookdata* data, struct elf_context* elf)
{
    // Find printf and exit from the symbol table
    struct elf_section_data symtab = elf_read_section_data(elf, ".symtab");
    size_t sym_count = symtab.size / sizeof(Elf64_Sym);
    for (size_t i = 0; i < sym_count; ++i)
    {
        const Elf64_Sym* sym = (Elf64_Sym*)symtab.data + i;
        char sym_name[256] = {0};
        elf_read_symbol_string(elf, sym->st_name, sym_name);
        
        if (!strcmp(sym_name, data->function))
        {
            data->function_address = sym->st_value;
            return;
        }
    }
}

void hookdata_convert_addresses(struct elf_context* elf)
{
    for (size_t i = 0; i < hookdata_count; ++i)
        hookdata_convert_address(hookdata_list + i, elf);
}