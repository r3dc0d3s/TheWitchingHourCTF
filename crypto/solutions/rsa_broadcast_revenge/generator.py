from Crypto.Util.number import getPrime, bytes_to_long
import time

# --- The Founder's Revenge ---
flag = b"CTF{th3_p4st_c4tch3s_up_t0_y0u}"
m = bytes_to_long(flag)
e = 3

# Generate 3 different moduli
n1 = getPrime(512) * getPrime(512)
n2 = getPrime(512) * getPrime(512)
n3 = getPrime(512) * getPrime(512)

# Generate a base timestamp and small deltas
base_timestamp = time.time_ns() // 1000 * 1000
delta1 = 12345
delta2 = 23456
delta3 = 34567

# Construct the messages
m1 = (m << 64) + (base_timestamp + delta1)
m2 = (m << 64) + (base_timestamp + delta2)
m3 = (m << 64) + (base_timestamp + delta3)

# Encrypt the new, timestamped messages
c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)
c3 = pow(m3, e, n3)

output = f"""--- The Founder's Revenge ---
Recover the secret key from the intercepted data.

e = {e}
Base Timestamp (ns): {base_timestamp}
Timestamp Deltas (ns): [{delta1}, {delta2}, {delta3}]
--------------------
n1 = {n1}
c1 = {c1}
--------------------
n2 = {n2}
c2 = {c2}
--------------------
n3 = {n3}
c3 = {c3}
"""

with open("rsa_broadcast_revenge/challenge.txt", "w") as f:
    f.write(output)

print("[+] Created 'rsa_broadcast_revenge/challenge.txt'")