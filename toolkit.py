import re, math, warnings, os, tempfile, subprocess, time, string

def repr_to_bytes(repr: str, base: int = None, endian='big') -> bytes:
    s = re.sub(r'\s', '', repr).lower()
    if not base:
        try:
            int(s, 2)
        except ValueError:
            try:
                int(s, 10)
            except ValueError:
                base = 16
            else:
                base = 10
        else:
            base = 2
        warnings.warn('No explicit base specified. Decoded %s using base %d' % (repr, base))
    n = int(s, base)
    if n!=0:
        return n.to_bytes(int(math.ceil(math.log2(n) // 8) + 1), endian)
    else:
        return b'\0'


def repr_to_str(repr: str, base: int = None, endian='big') -> str:
    return repr_to_bytes(repr, base, endian).decode('latin1', )


def hex_to_bytes(repr: str, endian='big'):
    return repr_to_bytes(repr, 16, endian)


def hex_to_str(repr: str, endian='big') -> str:
    return repr_to_str(repr, 16, endian)


def dec_to_bytes(repr: str, endian='big') -> bytes:
    return repr_to_bytes(repr, 10, endian)


def dec_to_str(repr: str, endian='big') -> str:
    return repr_to_str(repr, 10, endian)


def bin_to_bytes(repr: str, endian='big') -> bytes:
    return repr_to_bytes(repr, 2, endian)


def bin_to_str(repr: str, endian='big') -> str:
    return repr_to_str(repr, 2, endian)


def hex_to_int(repr: str) -> int:
    s = re.sub(r'\s', '', repr).lower()
    return int(s, 16)


def bin_to_int(repr: str) -> int:
    s = re.sub(r'\s', '', repr).lower()
    return int(s, 2)


def int_to_hex(n: int, sep: int = 4) -> str:
    """
    :param sep: steps to separated by spaces. Set to 0 to disable
    """
    s = hex(n)[2:].upper()
    res = ''
    if sep:
        if len(s) % sep != 0:
            s = '0' * (sep - (len(s) % sep)) + s
        for i in range(sep, len(s) + 1, sep):
            res += s[i - sep:i] + ' '
        
        return res.strip()
    return s


def bin_to_hex(repr: str, sep: int = 4) -> str:
    """
    :param repr: Binary representation of the number
    :param sep: steps to separated by spaces. Set to 0 to disable
    """
    n = bin_to_int(repr)
    return int_to_hex(n, sep)


def int_to_bin(n: int, sep: int = 8) -> str:
    s = bin(n)[2:]
    res = ''
    if sep:
        if len(s) % sep != 0:
            s = '0' * (sep - (len(s) % sep)) + s
        for i in range(sep, len(s) + 1, sep):
            res += s[i - sep:i] + ' '
        
        return res.strip()
    return s

def int_to_str(n: int) -> str:
    return dec_to_str(str(n))


def hex_to_bin(repr: str, sep: int = 8) -> str:
    n = hex_to_int(repr)
    return int_to_bin(n, sep)


def scan_file(path):
    with tempfile.NamedTemporaryFile() as tmp:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        proc=subprocess.run('flawfinder --context --html %s' % path, stdout=tmp, shell=True)
        if proc.returncode==127:
            raise SystemExit('Please run `pip install flawfinder` first')
        tmp.flush()
        os.system('open %s' % tmp.name)
        time.sleep(2)  # wait to open the file


def connect(port):
    import pwn
    address='mercury.picoctf.net'
    r=pwn.remote(address,port)
    return r

def egcd(a: int, b: int):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a: int, m: int):
    """
    Finds the modular inverse given a number (a) and a modulus (m)
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def lcm(a: int, b: int):
    """Compute the lowest common multiple of a and b"""
    return a * b // gcd(a, b)

def factorize(n):
    """
    Factorizes the number given
    """
    import pyprimesieve
    return pyprimesieve.factorize(int(n))

def prime_sieve(n):
    """
    Finds all primes from 1 until n
    """
    import pyprimesieve
    return pyprimesieve.primes(int(n))

def send(r, msg):
    """
    Sends string to server
    Example setup:
    r = remote('2018shell2.picoctf.com', 50430)
    """
    r.send(str(msg) + '\n')

def interact(r):
    """
    Interacts with server
    Example setup:
    r = remote('2018shell2.picoctf.com', 50430)
    """
    r.interactive()
    exit(0)

def recv_line(r):
    return r.recvline().decode()

def throwaway(r, n: int):
    """
    Throw away n lines. Does not return anything.
    """
    for i in range(n-1):
        recv_line(r)

def b16_decode(plain):
    LOWERCASE_OFFSET = ord("a")
    ALPHABET = string.ascii_lowercase[:16]
    hex_alphabet = []
    string_hex = []
    for count, v in enumerate(plain):
        string_hex.append(ord(v) - LOWERCASE_OFFSET)

    result = ""
    for value in string_hex:
        result += int_to_hex(value, 0)

    return hex_to_str(result)


def b16_encode(plain):
    LOWERCASE_OFFSET = ord("a")
    ALPHABET = string.ascii_lowercase[:16]
    enc = ""
    for c in plain:
            binary = "{0:08b}".format(ord(c))
            enc += ALPHABET[int(binary[:4], 2)]
            enc += ALPHABET[int(binary[4:], 2)]
    return enc

