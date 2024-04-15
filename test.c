#include "sohook.h"

#include <stdio.h>
#include <unistd.h>

DEFINE_FUNC(0x1189, add_ptr, int, int, int);

DEFINE_HOOK(0x11F9, func_add, 0x5)
{
    R->rdi = add_ptr(R->rdi & 0xffffffff, R->rsi & 0xffffffff);
    return 0;
}
