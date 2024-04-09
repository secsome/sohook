#include "sohook.h"

#include <stdio.h>

DEFINE_HOOK(0x1189, dummy, 0xC)
{
    printf("I'm a dummy hook\n");
    return 0x120F;
}
