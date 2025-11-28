import socket
import random

HOST = '0.0.0.0'
PORT = 1341

class LCG:
    def __init__(self):
        # 64-bit unknown parameters
        self.m = random.getrandbits(64)
        self.a = random.getrandbits(64)
        self.c = random.getrandbits(64)
        self.state = random.getrandbits(64)
        
    def next_val(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

def challenge_logic(send_func, recv_func):
    lcg = LCG()
    
    send_func("-" * 40)
    send_func("      THE ORACLE OF NUMBERS")
    send_func("-" * 40)
    send_func("I see a pattern in the chaos.")
    send_func("I will give you 6 glimpses of the future.")
    send_func("You must give me the 7th.")
    send_func("-" * 40)
    
    # Give 6 numbers
    for i in range(6):
        val = lcg.next_val()
        send_func(f"Glimpse {i+1}: {val}")
        
    # Ask for the 7th
    expected = lcg.next_val()
    
    guess_str = recv_func("\nWhat comes next? > ")
    
    try:
        if int(guess_str) == expected:
            send_func("\n[+] VISION CONFIRMED.")
            send_func("    Flag: CyberZ{l1n34r_c0ngru3nc3_br34k3r_9000}")
        else:
          
          
          
            send_func(f"\n[-] BLINDNESS. The future was {expected}.")
    except (ValueError, TypeError):
        send_func("\n[-] That is not a number.")

def handle_connection(conn, addr):
    print(f"Connected by {addr}", flush=True)

    def send_to_client(message):
        conn.sendall((message + "\n").encode())
        
    def recv_from_client(prompt):
        if prompt:
            send_to_client(prompt)
        # Handle potential empty recv
        data = conn.recv(1024)
        if not data:
            return ""
        return data.decode().strip()
        
    try:
        challenge_logic(send_to_client, recv_from_client)
    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {addr} disconnected unexpectedly.", flush=True)
    except Exception as e:
        print(f"Error handling client {addr}: {e}", flush=True)
    finally:
        conn.close()
        print(f"Client {addr} disconnected.", flush=True)

def main():
    print("Starting server...", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"Binding to {HOST}:{PORT}...", flush=True)
        s.bind((HOST, PORT))
        s.listen()
        print(f"LCG Predictor Server listening on {HOST}:{PORT}", flush=True)
        
        while True:
            print("Waiting for connection...", flush=True)
            conn, addr = s.accept()
            # In a simple single-threaded server, we handle one connection at a time.
            # For concurrent connections, we would need threading or asyncio.
            handle_connection(conn, addr)

if __name__ == "__main__":
    main()