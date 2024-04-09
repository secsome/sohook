#include <stddef.h>

struct hookdecl_t
{
    void* address;
    size_t length;
    const char* function;
};

int MY_FUNCTION(int a, int b);
__attribute__((section(".sohook"))) struct hookdecl_t hookdecls[] = {
    { MY_FUNCTION, 5, "MY_FUNCTION" }
};
int MY_FUNCTION(int a, int b)
{
    return a + b;
}

