#include "dynamic.h"

#include <stddef.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/signal.h>

#include "utils.h"
#include "hookdata.h"
#include "debugger.h"

size_t dynamic_get_target_address(struct debugger_context* ctx, size_t address)
{
    address = debugger_restore_exe_va(ctx, address);
    struct hookdata* data = hookdata_find((void*)address);
    debugger_assert(ctx, data, "sohook: Hook data not found\n");
    return debugger_convert_lib_va(ctx, data->function_address);
}

void dynamic_main(struct debugger_context* ctx)
{
    // install all hooks as breakpoints
    for (size_t i = 0; i < hookdata_count; ++i)
    {
        const size_t exe_address = debugger_convert_exe_va(ctx, (size_t)hookdata_list[i].address);
        debugger_add_breakpoint(ctx, exe_address);
        struct breakpoint_t* bp = (struct breakpoint_t*)vector_at(&ctx->breakpoints, i);
        debugger_enable_breakpoint(ctx, bp);
    }

    while (true)
    {
        int status = debugger_continue(ctx);
        
        // If the child process is terminated, terminate the debugger
        if (WIFEXITED(status))
            break;

        // If the child process is stopped by 0xcc breakpoint, handle it
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            struct user_regs_struct regs = debugger_read_registers(ctx);
            size_t address = regs.rip - 1;
            struct breakpoint_t* bp = debugger_find_breakpoint(ctx, address);
            if (bp == NULL) // Not our hook breakpoint, ignore it
                continue;

            unsigned char nop = 0x90;
            debugger_assert(ctx,
                debugger_write_memory(ctx, address, &nop, sizeof(nop)),
                "sohook: Failed to write nop to hook address"
            );

            // Redirect to the shellcode
            struct user_regs_struct tmp_regs = regs;
            tmp_regs.rip = (size_t)ctx->shellcode_buffer + 0x800; // the shellcode is placed at 0x800
            tmp_regs.rdi = (size_t)ctx->shellcode_buffer; // store the address of the registers data in rax
            tmp_regs.rax = (size_t)dynamic_get_target_address(ctx, address); // address to the function in dynamic library
            debugger_write_registers(ctx, &tmp_regs);

            // call rax
            unsigned char jmp_shellcode[] = {0xff, 0xd0, 0xcc};
            
            debugger_assert(ctx,
                debugger_write_memory(ctx, (size_t)ctx->shellcode_buffer + 0x800, jmp_shellcode, sizeof(jmp_shellcode)),
                "sohook: Failed to write shellcode"
            );
            debugger_assert(ctx,
                debugger_write_memory(ctx, (size_t)ctx->shellcode_buffer, &regs, sizeof(struct user_regs_struct)),
                "sohook: Failed to write registers"
            );

            status = debugger_continue(ctx);
            debugger_assert(ctx, WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP, "sohook: Unexpected signal %d\n", WSTOPSIG(status));
                
            // Set current instruction to nop so that we can continue
            memset(jmp_shellcode, 0x90, sizeof(jmp_shellcode));
            debugger_assert(ctx,
                debugger_write_memory(ctx, (size_t)ctx->shellcode_buffer + 0x800, jmp_shellcode, sizeof(jmp_shellcode)),
                "sohook: Failed to write nops"
            );
            debugger_assert(ctx,
                debugger_read_memory(ctx, (size_t)ctx->shellcode_buffer,&tmp_regs, sizeof(tmp_regs)),
                "sohook: Failed to read registers"
            );

            // Get the return value
            size_t rax = debugger_read_register(ctx, RAX);
            if (rax == 0)
            {
                // return to original address
                tmp_regs.rip = address;
                debugger_write_registers(ctx, &tmp_regs);

                // Run the oringinal instruction
                debugger_disable_breakpoint(ctx, bp);
                status = debugger_singlestep(ctx);
                debugger_assert(ctx, WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP, "sohook: Unexpected signal %d\n", WSTOPSIG(status));
                
                // Reenable the breakpoint
                debugger_enable_breakpoint(ctx, bp);
            }
            else
            {
                // jump to the target address instead
                size_t new_rip = debugger_convert_exe_va(ctx, rax);

                // update the register and continue
                tmp_regs.rip = new_rip;
                debugger_write_registers(ctx, &tmp_regs);

                // restore the breakpoint
                unsigned char int3 = 0xcc;
                debugger_assert(ctx,
                    debugger_write_memory(ctx, address, &int3, sizeof(int3)),
                    "sohook: Failed to restore the breakpoint"
                );
            }
        }
    }

}