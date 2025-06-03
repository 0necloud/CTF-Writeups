from pwn import *
import itertools
from fractions import Fraction
import re

context.log_level = 'error'

# Expression Tree Node
class Node:
    def __init__(self, val=None, left=None, right=None, op=None):
        self.val = val
        self.left = left
        self.right = right
        self.op = op

    def eval(self):
        if self.val is not None:
            return Fraction(self.val)
        a = self.left.eval()
        b = self.right.eval()
        if self.op == '+':
            return a + b
        elif self.op == '-':
            if a - b < 0:
                raise ValueError()
            return a - b
        elif self.op == '*':
            return a * b
        elif self.op == '/':
            if b == 0 or a % b != 0:
                raise ValueError()
            return a / b
        raise ValueError()

    def __str__(self):
        if self.val is not None:
            return str(self.val)
        return f"({str(self.left)} {self.op} {str(self.right)})"

def build_expressions(nums):
    if len(nums) == 1:
        yield Node(val=nums[0])
        return
    for i in range(1, len(nums)):
        lefts = nums[:i]
        rights = nums[i:]
        for l in build_expressions(lefts):
            for r in build_expressions(rights):
                for op in ['+', '-', '*', '/']:
                    yield Node(left=l, right=r, op=op)

def find_expression(target, numbers):
    for perm in itertools.permutations(numbers):
        try:
            for tree in build_expressions(list(perm)):
                try:
                    val = tree.eval()
                    if val == target:
                        return str(tree)
                except:
                    continue
        except:
            continue
    return None

def parse_target_and_numbers(data):
    target_match = re.search(r"Target: (\d+)", data)
    nums_match = re.search(r"Nums: ([\d\s]+)", data)
    if not target_match or not nums_match:
        return None, None
    target = int(target_match.group(1))
    numbers = list(map(int, nums_match.group(1).strip().split()))
    return target, numbers

def solve_round(io):
    print("[*] Starting new round...")
    io.sendline(b's')
    print("[+] Sent: 's' to start a new round")
    data = io.recvuntil(b'Your Answer:')
    target, numbers = parse_target_and_numbers(data.decode())
    if target is None or numbers is None:
        print("Failed to parse puzzle.")
        return False
    print(f"[+] Solving: Target={target}, Numbers={numbers}")
    expr = find_expression(target, numbers)
    if expr:
        io.sendline(expr.encode())
        print(f"[+] Sent: {expr}")
        return True
    else:
        print("[-] No valid expression found.")
        return False

def main():
    io = remote("challs.nusgreyhats.org", 33401)
    io.recvuntil(b'> ')
    rounds = 0
    while True:
        ok = solve_round(io)
        if not ok:
            break
        rounds += 1
        print(f"[✔] Completed round #{rounds}\n")
    io.interactive()

if __name__ == "__main__":
    main()
