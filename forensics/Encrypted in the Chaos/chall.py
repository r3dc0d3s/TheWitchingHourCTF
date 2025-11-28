#!/usr/bin/env python3
from scapy.all import *
import os, base64, random, string
from Crypto.Cipher import AES

# ============================================================
# 1) Generate AES-GCM Key, Nonce, Encrypt Data
# ============================================================

full_key = os.urandom(32)          # AES‑256
nonce = os.urandom(12)             # GCM nonce
cipher = AES.new(full_key, AES.MODE_GCM, nonce=nonce)

plaintext = b"flag{lb49ch4ch4_k47r00_h4d_ly4m477}"
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

b64_cipher = base64.b64encode(ciphertext).decode()
b64_tag    = base64.b64encode(tag).decode()
b64_nonce  = nonce.hex()

# ============================================================
# 2) Split key into fragments
# ============================================================

frag1 = base64.b64encode(full_key[0:8]).decode()
frag2 = base64.b64encode(full_key[8:16]).decode()
frag3 = base64.b64encode(full_key[16:24]).decode()
frag4 = base64.b64encode(full_key[24:28]).decode()
frag5 = base64.b64encode(full_key[28:32]).decode()

print("[+] FULL KEY:", full_key.hex())
print("[+] FRAG1:", frag1)
print("[+] FRAG2:", frag2)
print("[+] FRAG3:", frag3)
print("[+] FRAG4:", frag4)
print("[+] FRAG5:", frag5)
print("[+] NONCE:", nonce.hex())
print("[+] TAG:", base64.b64encode(tag).decode())
print("[+] CIPHERTEXT:", base64.b64encode(ciphertext).decode())

# ============================================================
# 3) Create Packets
# ============================================================

client_ip = "10.66.6.13"
server_ip = "10.66.6.66"

pkts = []

# --- REAL PACKETS ---

pkts.append(
    IP(src=client_ip, dst=server_ip)/TCP(sport=44444,dport=443,flags="PA")/
    (b"CLIENT_HELLO|WITCH-EXT-FRAG1:" + frag1.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"SERVER_HELLO|MOON-NONCE:" + b64_nonce.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"TLS_EXT|COVEN-FRAG2:" + frag2.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=80,dport=44444,flags="PA")/
    (b"HTTP/1.1 200 OK\r\nX-Hex: FRAG3:" + frag3.encode() + b"\r\n\r\n")
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/UDP(sport=44444,dport=44445)/
    (b"ALT_BACKUP-FRAG4:" + frag4.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=9001,dport=44444,flags="PA")/
    (b"WS|FRAG5:" + frag5.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"CIPHER:" + b64_cipher.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"TAG:" + b64_tag.encode())
)

# ============================================================
# 4) Garbage and Noise Packets
# ============================================================

def rand_str(n):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


print("[*] Generating 1000 fake client-server packets...")
for _ in range(996):
    t = random.randint(1,3)
    if t == 1:
        # Fake TLS-like traffic
        pkts.append(IP(src=client_ip,dst=server_ip)/
                    TCP(sport=random.randint(40000,60000), dport=443, flags="PA")/
                    (b"\x16\x03\x01" + os.urandom(random.randint(20,100))))
    elif t == 2:
        # Fake HTTP request/response
        pkts.append(IP(src=client_ip,dst=server_ip)/
                    TCP(sport=random.randint(40000,60000), dport=80, flags="PA")/
                    ("GET /"+rand_str(8)+" HTTP/1.1\r\nHost:"+rand_str(5)+".com\r\n\r\n").encode())
    else:
        # Fake server app data
        pkts.append(IP(src=server_ip,dst=client_ip)/
                    TCP(sport=443,dport=random.randint(40000,60000), flags="PA")/
                    (b"\x17\x03\x03" + os.urandom(random.randint(30,120))))


def make_garbage_packet():
    t = random.randint(1,5)

    if t == 1:
        return IP(src="172.16."+str(random.randint(0,255))+"."+str(random.randint(1,254)),
                  dst="192.168."+str(random.randint(0,255))+"."+str(random.randint(1,254))) / \
               TCP(sport=random.randint(1000,65000), dport=443, flags="PA") / \
               (b"\x16\x03\x01" + os.urandom(random.randint(20,150)))

    if t == 2:
        return IP(src="10.0."+str(random.randint(0,254))+"."+str(random.randint(1,254)),
                  dst="10.0."+str(random.randint(0,254))+"."+str(random.randint(1,254))) / \
               TCP(sport=random.randint(1000,65000), dport=80, flags="PA") / \
               ("GET /"+rand_str(12)+" HTTP/1.1\r\nHost: "+rand_str(10)+".com\r\n\r\n").encode()

    if t == 3:
        return IP(src="8.8.4."+str(random.randint(2,254)),
                  dst="8.8.8.8") / \
               UDP(sport=random.randint(1000,65000), dport=53) / \
               DNS(rd=1, qd=DNSQR(qname=rand_str(6)+".xyz"))

    if t == 4:
        return IP(src="100.64."+str(random.randint(1,255))+"."+str(random.randint(1,255)),
                  dst="100.64."+str(random.randint(1,255))+"."+str(random.randint(1,255))) / \
               UDP(sport=random.randint(1000,65000), dport=random.randint(1000,65000)) / \
               os.urandom(random.randint(40,200))

    return IP(src="203.0.113."+str(random.randint(2,254)),
              dst="198.51.100."+str(random.randint(2,254))) / \
           TCP(sport=random.randint(1000,65000), dport=443, flags="PA") / \
           (b"\x17\x03\x03" + os.urandom(random.randint(30,200)))


print("[*] Adding 8000+ garbage packets...")
for _ in range(6996):
    pkts.append(make_garbage_packet())

# Shuffle for realism
random.shuffle(pkts)

# ============================================================
# 5) Save PCAP
# ============================================================

wrpcap("Encrypted_in_the_Chaos.pcap", pkts)
print(f"[+] Challenge written with {len(pkts)} packets.")
