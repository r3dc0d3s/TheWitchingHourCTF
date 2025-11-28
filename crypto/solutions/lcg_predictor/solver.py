import socket
import sys
from math import gcd, isqrt

# --- Factorization Helper ---
def get_factors(n):
    factors = set()
    for i in range(1, isqrt(n) + 1):
        if n % i == 0:
            factors.add(i)
            factors.add(n//i)
    return sorted(list(factors), reverse=True)

# --- Modular Inverse Helper ---
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None
    return x % m

# --- LCG Solving Logic ---
def solve_lcg(outputs):
    if len(outputs) < 5:
        raise ValueError("Need at least 5 outputs to solve LCG parameters.")

    d = [outputs[i+1] - outputs[i] for i in range(len(outputs) - 1)]

    v_values = [abs((d[i+1]*d[i+1]) - (d[i]*d[i+2])) for i in range(len(d) - 2) if d[i+1]*d[i+1] != d[i]*d[i+2]]
    if not v_values:
        raise Exception("Could not find suitable v_values (all were zero).")

    m_candidate = v_values[0]
    for v in v_values[1:]:
        m_candidate = gcd(m_candidate, v)

    if m_candidate == 0:
        raise Exception("Failed to recover m_candidate (it's 0).")

    # The GCD might be a multiple of the true modulus. Find the correct one.
    possible_ms = get_factors(m_candidate)
    max_output = max(outputs)
    
    m = None
    for f in possible_ms:
        if f > max_output:
            m = f
            # We take the largest factor that's bigger than the outputs
            # This is our best guess for m
            break
            
    if m is None:
        raise Exception(f"Could not find a suitable modulus from factors of {m_candidate}.")

    a = None
    for i in range(len(d) - 1):
        if d[i] == 0: continue # Cannot use 0 to find the inverse
        d_inv = modinv(d[i], m)
        if d_inv is not None:
            a = (d[i+1] * d_inv) % m
            # Verify this 'a' with another pair to be sure
            if i + 2 < len(d):
                if (a * d[i+1]) % m == d[i+2] % m:
                    break # Confirmed 'a'
                else:
                    a = None # This 'a' was wrong, keep searching
            else:
                break # Not enough data to verify, but it's our only guess
    
    if a is None:
        raise Exception("Could not find a consistent 'a' for the recovered modulus.")

    c = (outputs[1] - a * outputs[0]) % m
    
    return m, a, c

def predict_next(last_output, m, a, c):
    return (a * last_output + c) % m

# --- Socket Handling ---
def connect_and_solve(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # ... (rest of the socket handling code is the same)
        recv_buffer = b""
        outputs = []
        
        while len(outputs) < 6:
            try:
                data = s.recv(4096)
                if not data: break
                recv_buffer += data
                while b'\n' in recv_buffer:
                    line, recv_buffer = recv_buffer.split(b'\n', 1)
                    line_str = line.decode(errors='ignore').strip()
                    if line_str.startswith("Glimpse"):
                        val = int(line_str.split(":")[1].strip())
                        if val not in outputs: outputs.append(val)
                    elif "What comes next?" in line_str:
                        # Force break outer loop
                        while len(outputs) < 6: outputs.append(0) # Pad to break
                if len(outputs) >= 6: break
            except (BlockingIOError, InterruptedError): continue
            except Exception as e:
                print(f"Error while receiving data: {e}")
                break

        if len(outputs) < 6:
            print(f"[-] Did not receive 6 outputs. Got {len(outputs)}.")
            return

        print("[+] Received 6 outputs:")
        for o in outputs: print(f"  - {o}")

        try:
            m, a, c = solve_lcg(outputs)
            print(f"[+] Recovered parameters: m={m}, a={a}, c={c}")
            next_val = predict_next(outputs[-1], m, a, c)
            print(f"[+] Predicted next value: {next_val}")

            s.sendall(str(next_val).encode() + b"\n")
            
            response = s.recv(4096).decode(errors='ignore')
            print("\nServer Response:")
            print(response)

        except Exception as e:
            print(f"[-] Error during LCG solving: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <host> <port>")
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    connect_and_solve(host, port)
