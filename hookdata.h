#pragma once

#include <stdint.h>
#include <stddef.h>

#include "elfhelper.h"
#include "sohook.h"

struct hookdata
{
    void* address;
    size_t length;
    char* function;
    size_t function_address;
};

extern size_t hookdata_count;
extern struct hookdata* hookdata_list;

void hookdata_clear();

void hookdata_add(void* address, const char* function, size_t length);
struct hookdata* hookdata_find(void* address);

void hookdata_load_inj(const char *filename);
void hookdata_load_elf(const char *filename);

void hookdata_convert_address(struct hookdata* data, struct elf_context* elf);
void hookdata_convert_addresses(struct elf_context* elf);

void hookdata_verify();