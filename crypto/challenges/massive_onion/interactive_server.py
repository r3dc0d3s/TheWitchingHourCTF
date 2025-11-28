import socket
import random
import base64

HOST = '0.0.0.0'
PORT = 1342

def generate_onion():
    flag = b"CyberZ{y0u_ar3_th3_arch1t3ct_0f_y0ur_0wn_h3ll}"
    current = flag
    
    layers = random.randint(30, 50)
    
    print(f"Generating an onion with {layers} layers.")
    
    for _ in range(layers):
        # Encode -> Reverse
        current = base64.b64encode(current)[::-1]
        
    return current, layers

def handle_connection(conn, addr):
    with conn:
        print(f"Connected by {addr}")
        
        onion, layers = generate_onion()
        
        conn.sendall(b"--- The Massive Onion Protocol ---\n")
        conn.sendall(b"We've intercepted a deeply nested data structure, but its depth is inconsistent.\n")
        conn.sendall(b"Here is the ciphertext:\n\n")
        conn.sendall(onion + b"\n\n")
        conn.sendall(b"Good luck peeling.\n")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Massive Onion Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == "__main__":
    main()
