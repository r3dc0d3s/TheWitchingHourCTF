#!/usr/bin/env python3
import random
import sys

# 1. SETUP (Dynamic per connection)
# 64-bit unknown parameters
m = random.getrandbits(64)
a = random.getrandbits(64)
c = random.getrandbits(64)
state = random.getrandbits(64)

def next_val():
    global state
    state = (a * state + c) % m
    return state

# 2. THE INTERACTION
print("-" * 40, flush=True)
print("      THE ORACLE OF NUMBERS", flush=True)
print("-" * 40, flush=True)
print(f"I see a pattern in the chaos.", flush=True)
print(f"I will give you 6 glimpses of the future.", flush=True)
print(f"You must give me the 7th.", flush=True)
print("-" * 40, flush=True)

# Give 6 numbers
outputs = []
for i in range(6):
    val = next_val()
    outputs.append(val)
    print(f"Glimpse {i+1}: {val}", flush=True)

# Ask for the 7th
expected = next_val()

print("\nWhat comes next?", flush=True)
print("> ", end="", flush=True)

try:
    guess = sys.stdin.readline().strip()
    if not guess:
        sys.exit(0)
        
    if int(guess) == expected:
        print("\n[+] VISION CONFIRMED.", flush=True)
        print("    Flag: CyberZ{l1n34r_c0ngru3nc3_br34k3r_9000}", flush=True)
    else:
        print(f"\n[-] BLINDNESS. The future was {expected}.", flush=True)
except:
    sys.exit(0)