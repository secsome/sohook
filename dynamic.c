#include "dynamic.h"

#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "utils.h"

void dynamic_main(struct debugger_context* ctx)
{
    // TODO: implement the dynamic hooking
    
    
    // wait the child process to finish
    debugger_continue(ctx);
}