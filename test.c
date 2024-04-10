#include "sohook.h"

#include <stdio.h>

DEFINE_HOOK(0x11DD, dummy, 0x2)
{
    printf("Hooked!\n");
    printf("%llu %llu\n", R->rax, R->rdx);
    R->rax += R->rdx;
    return 0x11DF;
}
