from Crypto.Util.number import long_to_bytes
import gmpy2
import re

def parse_challenge_file(filename):
    with open(filename, 'r') as f:
        content = f.read()
    
    values = {}
    # Use regular expressions to find all variables
    matches = re.findall(r'(\w+)\s*=\s*(\d+)', content)
    for key, value in matches:
        values[key] = int(value)
        
    return values['e'], values['n1'], values['c1'], values['n2'], values['c2'], values['n3'], values['c3']

def chinese_remainder_theorem(remainders, moduli):
    if len(remainders) != len(moduli):
        raise ValueError("Number of remainders must equal number of moduli")

    N = 1
    for n_i in moduli:
        N *= n_i

    result = 0
    for r_i, n_i in zip(remainders, moduli):
        N_i = N // n_i
        y_i = pow(N_i, -1, n_i)
        result += r_i * N_i * y_i

    return result % N

try:
    e, n1, c1, n2, c2, n3, c3 = parse_challenge_file("rsa_broadcast/challenge2.txt")

    # System of congruences
    remainders = [c1, c2, c3]
    moduli = [n1, n2, n3]

    # Solve for m^e using CRT
    m_cubed = chinese_remainder_theorem(remainders, moduli)

    # Find the integer e-th root of m_cubed
    m, exact = gmpy2.iroot(m_cubed, e)

    if exact:
        print(f"Found integer {e}-th root: {m}")
        flag = long_to_bytes(int(m))
        print(f"Flag: {flag.decode()}")
    else:
        print("Could not find an integer root.")

except FileNotFoundError:
    print("Error: challenge2.txt not found. Please run the generator first.")
except KeyError as e:
    print(f"Error: Missing value in challenge file: {e}")