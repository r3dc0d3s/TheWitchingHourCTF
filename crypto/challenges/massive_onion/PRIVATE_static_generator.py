import base64

flag = b"CyberZ{y0u_ar3_th3_arch1t3ct_0f_y0ur_0wn_h3ll}"
current = flag
layers = 50

print(f"[*] Wrapping {layers} layers...")

for i in range(layers):
    # Encode -> Reverse
    current = base64.b64encode(current)[::-1]

with open("massive_onion/mirror_onion.txt", "wb") as f:
    f.write(current)

print("[+] Created 'mirror_onion.txt'")