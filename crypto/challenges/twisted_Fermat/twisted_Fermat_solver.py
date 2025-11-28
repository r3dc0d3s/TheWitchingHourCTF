from math import isqrt
import sys

def parse_challenge(filename):
    vals = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.split("=")
                vals[key.strip()] = int(value.strip())
    return vals['n'], vals['e'], vals['c']

print("[*] Reading 'fermat_challenge.txt'...")
try:
    n, e, c = parse_challenge("fermat_challenge.txt")
except FileNotFoundError:
    print("[-] Error: File not found. Run the generator first!")
    sys.exit(1)

print(f"[*] Loaded N ({n.bit_length()} bits). Starting Fermat Factorization...")

# Fermat's Attack
a = isqrt(n) + 1
while True:
    b2 = a*a - n
    b = isqrt(b2)
    if b*b == b2:
        break
    a += 1

p = a - b
q = a + b
print(f"[+] Factors found!")

# Decrypt
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)

try:
    flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    print(f"\n[+] FLAG: {flag}")
except:
    print("[-] Decryption failed (math was right, but format is weird).")