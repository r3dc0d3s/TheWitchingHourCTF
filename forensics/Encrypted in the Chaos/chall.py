#!/usr/bin/env python3
from scapy.all import *
import os, base64, random, string

# ============================================================
# 1) Generate Key Fragments
# ============================================================

full_key = os.urandom(32)

frag1 = base64.b64encode(full_key[0:8]).decode()
frag2 = base64.b64encode(full_key[8:16]).decode()
frag3 = base64.b64encode(full_key[16:24]).decode()
frag4 = base64.b64encode(full_key[24:28]).decode()
frag5 = base64.b64encode(full_key[28:32]).decode()

nonce = os.urandom(12)
b64nonce = nonce.hex()

print("[+] Full AES key:", full_key.hex())
print("[+] frag1:", frag1)
print("[+] frag2:", frag2)
print("[+] frag3:", frag3)
print("[+] frag4:", frag4)
print("[+] frag5:", frag5)
print("[+] NONCE:", b64nonce)

# Fake plaintext (Encrypted in fake form)
plaintext = b"CyberZ{6000_64rb463_7_7ru7h@103921}"
cipher = base64.b64encode(plaintext).decode()

client_ip = "10.10.0.2"
server_ip = "10.10.0.5"
pkts = []

# ============================================================
# 2) Real Packets Containing Key Fragments
# ============================================================

pkts.append(
    IP(src=client_ip, dst=server_ip)/TCP(sport=44444,dport=443,flags="PA")/
    (b"CLIENT_HELLO|EXT-FRAG1:" + frag1.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"SERVER_HELLO|NONCE:" + b64nonce.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"TLS_EXT|FRAG2:" + frag2.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=80,dport=44444,flags="PA")/
    (b"HTTP/1.1 200 OK\r\nX-Key: FRAG3:" + frag3.encode() + b"\r\n\r\n")
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/UDP(sport=44444,dport=44445)/
    (b"BACKUP-FRAG4:" + frag4.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=9001,dport=44444,flags="PA")/
    (b"WS|FRAG5:" + frag5.encode())
)

pkts.append(
    IP(src=server_ip, dst=client_ip)/TCP(sport=443,dport=44444,flags="PA")/
    (b"ENCRYPTED:" + cipher.encode())
)

# ============================================================
# 3) Add 5000 Garbage Packets
# ============================================================

def rand_str(n):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def make_garbage_packet():
    t = random.randint(1,5)

    # Random TLS-like garbage
    if t == 1:
        return IP(src="192.168.1."+str(random.randint(2,254)),
                  dst="172.16.0."+str(random.randint(2,254))) / \
               TCP(sport=random.randint(1000,65000),
                   dport=443, flags="PA") / \
               (b"\x16\x03\x01" + os.urandom(random.randint(20,150)))

    # Random HTTP junk
    if t == 2:
        return IP(src="10.0."+str(random.randint(1,254))+"."+str(random.randint(1,254)),
                  dst="10.0."+str(random.randint(1,254))+"."+str(random.randint(1,254))) / \
               TCP(sport=random.randint(1000,65000), dport=80, flags="PA") / \
               ("GET /"+rand_str(10)+" HTTP/1.1\r\nHost: "+rand_str(8)+".com\r\n\r\n").encode()

    # Random DNS junk
    if t == 3:
        return IP(src="8.8.4."+str(random.randint(2,254)),
                  dst="8.8.8.8") / \
               UDP(sport=random.randint(1000,65000), dport=53) / \
               DNS(rd=1, qd=DNSQR(qname=rand_str(5)+".xyz"))

    # Random UDP junk
    if t == 4:
        return IP(src="100.64."+str(random.randint(1,255))+"."+str(random.randint(1,255)),
                  dst="100.64."+str(random.randint(1,255))+"."+str(random.randint(1,255))) / \
               UDP(sport=random.randint(1000,65000), dport=random.randint(1000,65000)) / \
               os.urandom(random.randint(20,200))

    # Random fake AppData
    return IP(src="203.0.113."+str(random.randint(2,254)),
              dst="198.51.100."+str(random.randint(2,254))) / \
           TCP(sport=random.randint(1000,65000), dport=443, flags="PA") / \
           (b"\x17\x03\x03" + os.urandom(random.randint(30,200)))



# ============================================================
# 3b) Add 1000 fake client-server packets
# ============================================================

print("[*] Generating 1000 fake client-server packets...")
for _ in range(1000):
    t = random.randint(1,3)
    if t == 1:
        # Fake TLS-like traffic
        pkts.append(
            IP(src=client_ip, dst=server_ip)/
            TCP(sport=random.randint(40000,60000), dport=443, flags="PA")/
            (b"\x16\x03\x01" + os.urandom(random.randint(20,100)))
        )
    elif t == 2:
        # Fake HTTP request/response
        pkts.append(
            IP(src=client_ip, dst=server_ip)/
            TCP(sport=random.randint(40000,60000), dport=80, flags="PA")/
            ("GET /"+rand_str(8)+" HTTP/1.1\r\nHost: "+rand_str(5)+".com\r\n\r\n").encode()
        )
    else:
        # Fake encrypted app data
        pkts.append(
            IP(src=server_ip, dst=client_ip)/
            TCP(sport=443, dport=random.randint(40000,60000), flags="PA")/
            (b"\x17\x03\x03" + os.urandom(random.randint(30,120)))
        )



print("[*] Generating 6000 garbage packets...")
for _ in range(5000):
    pkts.append(make_garbage_packet())





random.shuffle(pkts)


# ============================================================
# 4) Write PCAP
# ============================================================

wrpcap("Encrypted_in_the_Chaos.pcap", pkts)
print("[+] PCAP written with", len(pkts), "packets.")
