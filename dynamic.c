#include "dynamic.h"

#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "utils.h"

void dynamic_main(pid_t pid, const char* executable)
{
    // TODO: implement the dynamic hooking
    utils_dump_pid_maps(pid);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // wait the child process to finish
    int status;
    waitpid(pid, &status, 0);
}