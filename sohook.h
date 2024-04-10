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
};

#define __STR(x) #x

#define DEFINE_HOOK(addr, name, size) \
size_t _func_ ## name ## _(struct user_regs_struct* R); \
__attribute__((section(".sohook"))) struct hookdecl_t _ ## name ## _hookdecls_ = { (void*)addr, size, __STR(_func_ ## name ## _) }; \
size_t _func_ ## name ## _(struct user_regs_struct* R)

#ifdef __cplusplus
}
#endif