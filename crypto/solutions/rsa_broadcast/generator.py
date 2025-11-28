from Crypto.Util.number import getPrime, bytes_to_long

flag = b"CyberZ{sm4ll_3xp0n3nts_c4us3_br04dc4st_pr0bl3ms}"
m = bytes_to_long(flag)
e = 3

# Generate 3 different moduli
n1 = getPrime(512) * getPrime(512)
n2 = getPrime(512) * getPrime(512)
n3 = getPrime(512) * getPrime(512)

# Encrypt the SAME message 3 times
c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

output = f"""e = {e}
n1 = {n1}
c1 = {c1}
--------------------
n2 = {n2}
c2 = {c2}
--------------------
n3 = {n3}
c3 = {c3}
"""

with open("rsa_broadcast/challenge2.txt", "w") as f:
    f.write(output)

print("[+] Created 'rsa_broadcast/challenge2.txt'")