#!/usr/bin/env python3
from scapy.all import *
import base64
import re
from Crypto.Cipher import AES

pcap = "Encrypted_in_the_Chaos.pcap"

print("[*] Reading PCAP...")
pkts = rdpcap(pcap)

frag = [None]*6
nonce = None
cipher = None
tag = None

for p in pkts:
    if not p.haslayer(Raw):
        continue

    data = bytes(p[Raw])

    # FRAG 1
    m = re.search(rb"WITCH-EXT-FRAG1:([A-Za-z0-9+/=]+)", data)
    if m: frag[1] = m.group(1); print("[+] Found FRAG1:", frag[1].decode())

    # NONCE
    m = re.search(rb"MOON-NONCE:([0-9a-fA-F]+)", data)
    if m: nonce = bytes.fromhex(m.group(1).decode()); print("[+] Found NONCE:", m.group(1).decode())

    # FRAG 2
    m = re.search(rb"COVEN-FRAG2:([A-Za-z0-9+/=]+)", data)
    if m: frag[2] = m.group(1); print("[+] Found FRAG2:", frag[2].decode())

    # FRAG 3
    m = re.search(rb"FRAG3:([A-Za-z0-9+/=]+)", data)
    if m: frag[3] = m.group(1); print("[+] Found FRAG3:", frag[3].decode())

    # FRAG 4
    m = re.search(rb"ALT_BACKUP-FRAG4:([A-Za-z0-9+/=]+)", data)
    if m: frag[4] = m.group(1); print("[+] Found FRAG4:", frag[4].decode())

    # FRAG 5
    m = re.search(rb"FRAG5:([A-Za-z0-9+/=]+)", data)
    if m: frag[5] = m.group(1); print("[+] Found FRAG5:", frag[5].decode())

    # CIPHER
    m = re.search(rb"CIPHER:([A-Za-z0-9+/=]+)", data)
    if m: cipher = base64.b64decode(m.group(1)); print("[+] Found Ciphertext")

    # TAG
    m = re.search(rb"TAG:([A-Za-z0-9+/=]+)", data)
    if m: tag = base64.b64decode(m.group(1)); print("[+] Found TAG")

# Check
if None in frag[1:] or nonce is None or cipher is None or tag is None:
    print("[!] Missing data! Can't decrypt.")
    exit()

# Reassemble key
key_bytes = (
    base64.b64decode(frag[1]) +
    base64.b64decode(frag[2]) +
    base64.b64decode(frag[3]) +
    base64.b64decode(frag[4]) +
    base64.b64decode(frag[5])
)
print("\n[+] Reassembled Key:", key_bytes.hex())

# Decrypt AES-GCM
cipher_obj = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
plaintext = cipher_obj.decrypt_and_verify(cipher, tag)

print("\n[+] FLAG:", plaintext.decode())
