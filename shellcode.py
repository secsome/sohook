from keystone import *
from pprint import pprint

ks = Ks(KS_ARCH_X86, KS_MODE_64)

asm_entrypoint, asm_count = ks.asm(
    """
    mov rax, 29
    mov rdi, 0x987254ab
    mov rsi, 0x1000
    mov rdx, 01666
    syscall
    mov rdi, rax
    mov rax, 30
    xor rsi, rsi
    xor rdx, rdx
    syscall
    """
)

pprint(asm_entrypoint)
pprint(len(asm_entrypoint))