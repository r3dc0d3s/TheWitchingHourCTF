import socket
import threading
import time
import sys

# Add the current directory to the path to allow importing the server
sys.path.append('.')

from lcg_predictor import server as lcg_server

def run_server():
    print("[Test Script] Starting server thread...")
    try:
        lcg_server.main()
    except Exception as e:
        print(f"[Test Script] Server thread crashed: {e}", flush=True)

def run_client():
    print("[Test Script] Client thread waiting for server to start...", flush=True)
    time.sleep(2)
    
    HOST = lcg_server.HOST
    PORT = lcg_server.PORT
    
    print(f"[Test Script] Client attempting to connect to {HOST}:{PORT}...", flush=True)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5) # 5 second timeout
            s.connect((HOST, PORT))
            print("[Test Script] Client successfully connected!", flush=True)
            # Just receive the banner and close
            banner = s.recv(1024)
            print(f"[Test Script] Received banner: {banner.decode()}", flush=True)
    except Exception as e:
        print(f"[Test Script] Client connection failed: {e}", flush=True)

if __name__ == "__main__":
    # Run the server in a daemon thread so it exits when the main script exits
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Run the client test in the main thread
    run_client()
    
    print("[Test Script] Test finished.", flush=True)
