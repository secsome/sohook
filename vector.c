#include "vector.h"

#include <stdlib.h>
#include <string.h>

#define VECTOR_INITIAL_CAPACITY 8

void _vector_init(struct vector_t* this, size_t item_size)
{
    this->item_size = item_size;
    this->begin = malloc(VECTOR_INITIAL_CAPACITY * item_size);
    this->end = this->begin;
    this->final = (char*)this->begin + VECTOR_INITIAL_CAPACITY * item_size;
}

void vector_emplace(struct vector_t* this, void* item)
{
    if ((char*)this->end == (char*)this->final)
    {
        size_t capacity = (char*)this->final - (char*)this->begin;
        this->begin = realloc(this->begin, capacity * 2);
        this->end = (char*)this->begin + capacity;
        this->final = (char*)this->begin + capacity * 2;
    }

    memcpy(this->end, item, this->item_size);
    this->end = (char*)this->end + this->item_size;
}

void vector_clear(struct vector_t* this)
{
    free(this->begin);
    this->begin = NULL;
    this->end = NULL;
    this->final = NULL;
}

size_t vector_size(struct vector_t* this)
{
    return ((char*)this->end - (char*)this->begin) / this->item_size;
}

void* vector_at(struct vector_t* this, size_t index)
{
    return (char*)this->begin + index * this->item_size;
}


