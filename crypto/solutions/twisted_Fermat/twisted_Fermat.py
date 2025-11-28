from Crypto.Util.number import getPrime, isPrime, bytes_to_long

flag = b"CyberZ{f3rm4t_kn3w_th3_d1ff3r3nc3_0f_squ4r3s}"
m = bytes_to_long(flag)
e = 65537

print("[*] Generating vulnerable primes...")

# Generate p
p = getPrime(1024)

# Generate q close to p (The Flaw)
# Gap of 2^26 is tiny relative to 1024-bit primes
gap = 2**26 
q = p + gap
while not isPrime(q): 
    q += 1

n = p * q
c = pow(m, e, n)

# Output for the player
output = f"n = {n}\ne = {e}\nc = {c}"

with open("fermat_challenge.txt", "w") as f:
    f.write(output)

print("[+] DONE. Created 'fermat_challenge.txt'")