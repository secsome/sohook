#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>

#ifdef __cplusplus
extern "C" {
#endif

union register_item
{
    uint64_t qword;
    int64_t sqword;
    uint32_t dwords[2];
    int32_t sdwords[2];
    uint16_t words[4];
    int16_t swords[4];
    uint8_t bytes[8];
    int8_t sbytes[8];
};

struct REGISTERS
{
    union register_item r15;
    union register_item r14;
    union register_item r13;
    union register_item r12;
    union register_item rbp;
    union register_item rbx;
    union register_item r11;
    union register_item r10;
    union register_item r9;
    union register_item r8;
    union register_item rax;
    union register_item rcx;
    union register_item rdx;
    union register_item rsi;
    union register_item rdi;
    union register_item orig_rax;
    union register_item rip;
    union register_item cs;
    union register_item eflags;
    union register_item rsp;
    union register_item ss;
    union register_item fs_base;
    union register_item gs_base;
    union register_item ds;
    union register_item es;
    union register_item fs;
    union register_item gs;
};

struct hookdecl_t
{
    void* address;
    size_t length;
    const char* function;
    char padding[8];
};

#define __STR(x) #x

#define DEFINE_HOOK(addr, name, size) \
size_t _func_ ## name ## _(struct REGISTERS* R); \
__attribute__((section(".sohook"))) struct hookdecl_t _ ## name ## _hookdecls_ = { (void*)addr, size, __STR(_func_ ## name ## _) }; \
size_t _func_ ## name ## _(struct REGISTERS* R)

struct funcdecl_t
{
    void* address;
    const char* function;
};

#define DEFINE_FUNC(addr, name, return_type, ...) \
__attribute__((section(".sofunc"))) struct funcdecl_t _ ## name ## _funcdecls_ = { (void*)addr, __STR(name) }; \
return_type (*name)(__VA_ARGS__) = (return_type(*)(__VA_ARGS__))addr

#define DEFINE_FUNC_EX(addr, name, return_type, call_conv, ...) \
__attribute__((section(".sofunc"))) struct funcdecl_t _ ## name ## _funcdecls_ = { (void*)addr, __STR(name) }; \
return_type (call_conv *name)(__VA_ARGS__) = (return_type(call_conv *)(__VA_ARGS__))addr

#ifdef __cplusplus
}
#endif