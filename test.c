#include "sohook.h"

#include <stdio.h>
#include <unistd.h>

DEFINE_FUNC(0x1189, add_ptr, int, int, int);

DEFINE_HOOK(0x11F9, func_add, 0x5)
{
    R->rdi.dwords[0] = add_ptr(R->rdi.dwords[0], R->rsi.dwords[0]);
    return 0;
}
