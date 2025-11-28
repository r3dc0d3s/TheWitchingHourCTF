from pwn import *
import sys

# Disable logging by default
context.log_level = 'error'

def connect_and_solve(host, port):
    try:
        # Start local server (if running as a subprocess) or connect remotely
        if host == 'localhost' or host == '127.0.0.1':
            io = process(['python3', 'cbc/server.py']) # Assuming server.py is in the same directory
        else:
            io = remote(host, port)

        # 1. Register Payload
        # Align ";role=guest" to the start of Block 2
        # "user=" is 5 bytes. 11 "A"s make Block 1 full (16 bytes).
        # Block 2 will start with ";role=guest"
        username = "A" * 11 # 11 A's. This makes the first block "user=AAAAAAAAAAA;" (16 bytes)

        log.info(f"[*] Sending username: {username}")
        io.recvuntil(b"> ")
        io.sendline(b"1")
        io.recvuntil(b"Username: ")
        io.sendline(username.encode())

        # 2. Capture Token
        io.recvuntil(b"Token: ")
        token_hex = io.recvline().strip().decode()
        log.info(f"[*] Original Token (hex): {token_hex}")
        token = bytearray.fromhex(token_hex)

        # 3. The Bit Flip
        # Block 2 (plaintext) is ";role=guest..."
        # We want to change "guest" to "admin"
        # The bytes to change are at indices 6, 7, 8, 9, 10 within Block 2's plaintext.
        # In CBC, to change P[i], we modify C[i-1]
        # P[i] = D(C[i]) XOR C[i-1]
        # P'[i] = D(C[i]) XOR C'[i-1]
        # C'[i-1] = C[i-1] XOR P[i] XOR P'[i]

        # The ciphertext blocks are IV || C1 || C2.
        # The token provided is C1 || C2.
        # Here, the 'token' variable contains C1 || C2.
        # We want to change P2, so we modify C1.
        # The specific bytes are in C1.

        # Let's verify block alignment and content if possible
        # original P1 = b"user=AAAAAAAAAAA"
        # original P2 = b";role=guest" + padding

        # Indices to flip in the plaintext block 2 for "guest" -> "admin"
        # The ';role=' part is 6 bytes. So 'g' is at index 6 of P2.
        # In the ciphertext block C1 (which affects P2), we need to flip the bytes at the same indices.
        
        # Flips: (index in C1, original_char_in_P2, target_char_in_P2)
        flips = [
            (6, ord('g'), ord('a')),
            (7, ord('u'), ord('d')),
            (8, ord('e'), ord('m')),
            (9, ord('s'), ord('i')),
            (10, ord('t'), ord('n'))
        ]

        # Apply the flips to the first ciphertext block (C1)
        # Note: the `token` bytearray represents C1 || C2 || ...
        # C1 is token[0:16]
        for index_in_P2, original_byte, target_byte in flips:
            # We need to flip the byte in C1 at the same index
            # This logic assumes the block of C1 corresponds directly to the plaintext block
            # For CBC bit-flipping, this is correct: C1[j] affects P2[j]
            token[index_in_P2] ^= (original_byte ^ target_byte)

        log.info(f"[*] Flipped 'guest' to 'admin'. Tampered Token (hex): {token.hex()}")

        # 4. Login
        io.recvuntil(b"> ")
        io.sendline(b"2")
        io.recvuntil(b"Token: ")
        io.sendline(token.hex().encode())

        # 5. Check Success
        io.interactive() # This will show the final output
        io.close() # Close the process

    except Exception as e:
        log.error(f"Solver failed: {e}")
        if 'io' in locals() and io.connected:
            io.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <host> <port>")
        sys.exit(1)
        
    host, port = sys.argv[1], int(sys.argv[2])
    connect_and_solve(host, port)