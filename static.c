#include "dynamic.h"

#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "utils.h"

void static_main(struct debugger_context* ctx)
{
    // TODO: implement the static hooking
    
    
    // wait the child process to finish
    debugger_continue(ctx);
}