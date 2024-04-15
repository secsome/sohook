#pragma once

#include <stddef.h>
#include <sys/user.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hookdecl_t
{
    void* address;
    size_t length;
    const char* function;
    char padding[8];
};

#define __STR(x) #x

#define DEFINE_HOOK(addr, name, size) \
size_t _func_ ## name ## _(struct user_regs_struct* R); \
__attribute__((section(".sohook"))) struct hookdecl_t _ ## name ## _hookdecls_ = { (void*)addr, size, __STR(_func_ ## name ## _) }; \
size_t _func_ ## name ## _(struct user_regs_struct* R)

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