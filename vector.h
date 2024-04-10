#pragma once

#include <stddef.h>

struct vector_t
{
    size_t item_size;
    void* begin;
    void* end;
    void* final;
};

void _vector_init(struct vector_t* this, size_t item_size);
void vector_destroy(struct vector_t* this);
void vector_emplace(struct vector_t* this, void* item);
void vector_clear(struct vector_t* this);
size_t vector_size(struct vector_t* this);
void* vector_at(struct vector_t* this, size_t index);

#define vector_init(this, type) _vector_init(this, sizeof(type))