import socket
import random
import time

HOST = '0.0.0.0'
PORT = 1344

FLAG = "CyberZ{m3rs3nn3_tw1st3r_stat3_r3c0v3ry_w1n}"

def challenge_logic(send_func, recv_func):
    # Seed the random number generator
    seed = int(time.time() * 1000) # Use a time-based seed for variation
    random.seed(seed)

    # MT19937 requires 624 outputs to reconstruct its state
    num_outputs_to_give = 624
    
    send_func("-" * 40)
    send_func("      THE TWISTED ORACLE")
    send_func("-" * 40)
    send_func("I can predict the unpredictable!")
    send_func(f"I will give you {num_outputs_to_give} outputs from my mind.")
    send_func("You must give me the very next one.")
    send_func("-" * 40)
    
    outputs = []
    for i in range(num_outputs_to_give):
        val = random.getrandbits(32) # Standard output size for MT19937
        outputs.append(val)
        send_func(f"Output {i+1}: {val}")
        
    # The expected next value after revealing the state
    expected = random.getrandbits(32)
    
    guess_str = recv_func("\nWhat is the next output? > ")
    
    try:
        if int(guess_str) == expected:
            send_func("\n[+] YOU HAVE TWISTED MY ARM! Vision confirmed.")
            send_func(f"    Flag: {FLAG}")
        else:
            send_func(f"\n[-] YOU ARE NOT WORTHY. The next output was {expected}.")
    except ValueError:
        send_func("\n[-] That is not a number.")

def handle_connection(conn, addr):
    print(f"Connected by {addr}")

    def send_to_client(message):
        conn.sendall((message + "\n").encode())
        
    def recv_from_client(prompt):
        send_to_client(prompt)
        data = conn.recv(1024).decode().strip()
        return data
        
    try:
        challenge_logic(send_to_client, recv_from_client)
    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {addr} disconnected unexpectedly.")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Client {addr} disconnected.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Mersenne LCG Predictor Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == "__main__":
    main()
