#!/usr/bin/env python3
from scapy.all import *
import base64
import re

pcap = "Encrypted_in_the_Chaos.pcap"

print("[*] Reading PCAP...")
pkts = rdpcap(pcap)

frag = [None]*6
nonce = None
cipher = None

for p in pkts:
    if not p.haslayer(Raw):
        continue

    data = bytes(p[Raw])

    # ----------------------------
    # FRAG 1
    # ----------------------------
    m = re.search(rb"EXT-FRAG1:([A-Za-z0-9+/=]+)", data)
    if m:
        frag[1] = m.group(1)
        print("[+] Found FRAG1:", frag[1].decode())

    # ----------------------------
    # NONCE
    # ----------------------------
    m = re.search(rb"NONCE:([0-9a-fA-F]+)", data)
    if m:
        nonce = m.group(1).decode()
        print("[+] Found NONCE:", nonce)

    # ----------------------------
    # FRAG 2
    # ----------------------------
    m = re.search(rb"FRAG2:([A-Za-z0-9+/=]+)", data)
    if m:
        frag[2] = m.group(1)
        print("[+] Found FRAG2:", frag[2].decode())

    # ----------------------------
    # FRAG 3
    # ----------------------------
    m = re.search(rb"FRAG3:([A-Za-z0-9+/=]+)", data)
    if m:
        frag[3] = m.group(1)
        print("[+] Found FRAG3:", frag[3].decode())

    # ----------------------------
    # FRAG 4
    # ----------------------------
    m = re.search(rb"BACKUP-FRAG4:([A-Za-z0-9+/=]+)", data)
    if m:
        frag[4] = m.group(1)
        print("[+] Found FRAG4:", frag[4].decode())

    # ----------------------------
    # FRAG 5
    # ----------------------------
    m = re.search(rb"FRAG5:([A-Za-z0-9+/=]+)", data)
    if m:
        frag[5] = m.group(1)
        print("[+] Found FRAG5:", frag[5].decode())

    # ----------------------------
    # CIPHER
    # ----------------------------
    m = re.search(rb"ENCRYPTED:([A-Za-z0-9+/=]+)", data)
    if m:
        cipher = m.group(1)
        print("[+] Found Encrypted blob:", cipher.decode())

print("\n=== SUMMARY ===")

print("Fragments:", frag)
print("Nonce:", nonce)
print("Cipher:", cipher)

if None in frag[1:]:
    print("[!] Missing one or more fragments")
    exit()

if cipher is None:
    print("[!] Missing encrypted message!")
    exit()

# ============================================
# REASSEMBLE KEY
# ============================================

key_bytes = (
    base64.b64decode(frag[1]) +
    base64.b64decode(frag[2]) +
    base64.b64decode(frag[3]) +
    base64.b64decode(frag[4]) +
    base64.b64decode(frag[5])
)

print("\n[+] Reassembled Key:", key_bytes.hex())
print("[+] Key length:", len(key_bytes))

# ============================================
# DECRYPT MESSAGE (BASE64 ONLY — fake TLS)
# ============================================

plaintext = base64.b64decode(cipher)
print("\n[+] Plaintext:", plaintext.decode(errors="ignore"))
