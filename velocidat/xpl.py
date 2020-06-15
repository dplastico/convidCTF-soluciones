from pwn import *
### conectando ###
r = remote('l4tinhtb.com', 1337)
###recibiendo payload y fuiltrando ###
resp = r.recv().split(" ")
### calculando ###
a = int(resp[0],16)
b = int(resp[4].split("\n")[0],16)
c = a ^ b
### enviando respuesta ###
r.sendline(hex(c))
r.interactive()

