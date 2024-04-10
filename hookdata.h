#pragma once

#include <stdint.h>
#include <stddef.h>

struct hookdata
{
    void* address;
    size_t length;
    char* function;
};

extern size_t hookdata_count;
extern struct hookdata* hookdata_list;

void hookdata_clear();

void hookdata_add(void* address, const char* function, size_t length);

void hookdata_load_inj(const char *filename);

void hookdata_load_elf(const char *filename);

void hookdata_verify();