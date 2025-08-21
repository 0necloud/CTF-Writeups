import random
import time

def genToken(seed:str) -> str:
    random.seed(seed)
    return ''.join(random.choices('abcdef0123456789', k=16))

current_time = time.time()

for delta in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
    token = genToken(int(time.time() + delta) // 1)
    print(f"Token (delta={delta}): {token}")