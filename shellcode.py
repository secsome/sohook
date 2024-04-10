from keystone import *
from pprint import pprint

ks = Ks(KS_ARCH_X86, KS_MODE_64)

asm_entrypoint, asm_count = ks.asm(
    """
    mov rax, 9
    mov rdi, 0
    mov rsi, 0x1000
    mov rdx, 7
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    syscall
    int3
    """
)

for i in range(len(asm_entrypoint)):
    print(f'0x{asm_entrypoint[i]:02x}, ', end='')
print('')

asm_transfer, asm_count = ks.asm(
    """
    call rax
    int3
    """
)

pprint(asm_transfer)
pprint(len(asm_entrypoint))