import base64

with open("mirror_onion.txt", "rb") as f:
    data = f.read()

print("[*] Peeling onion...")
while b"CyberZ{" not in data:
    try:
        # Reverse -> Decode
        data = base64.b64decode(data[::-1])
    except:
        break

print(f"[+] Flag: {data.decode()}")