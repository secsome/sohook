#include "dynamic.h"

#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

void dynamic_main(pid_t pid)
{
    // TODO: implement the dynamic hooking
    
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // wait the child process to finish
    int status;
    waitpid(pid, &status, 0);
}