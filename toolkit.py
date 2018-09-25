import pwn, re, math, warnings, os, tempfile, subprocess, time


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
    return n.to_bytes(int(math.ceil(math.log2(n) // 8) + 1), endian)


def repr_to_chars(repr: str, base: int = None, endian='big') -> str:
    return repr_to_bytes(repr, base, endian).decode('latin1', )


def hex_to_bytes(repr: str, endian='big'):
    return repr_to_bytes(repr, 16, endian)


def hex_to_chars(repr: str, endian='big') -> str:
    return repr_to_chars(repr, 16, endian)


def dec_to_bytes(repr: str, endian='big') -> bytes:
    return repr_to_bytes(repr, 10, endian)


def dec_to_chars(repr: str, endian='big') -> str:
    return repr_to_chars(repr, 10, endian)


def bin_to_bytes(repr: str, endian='big') -> bytes:
    return repr_to_bytes(repr, 2, endian)


def bin_to_chars(repr: str, endian='big') -> str:
    return repr_to_chars(repr, 2, endian)


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


def hex_to_bin(repr: str, sep: int = 8) -> str:
    n = hex_to_int(repr)
    return int_to_bin(n, sep)


def scan_sourcecode(path):
    with tempfile.NamedTemporaryFile() as tmp:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        proc=subprocess.run('flawfinder --context --html %s' % path, stdout=tmp, shell=True)
        if proc.returncode==127:
            raise SystemExit('Please run `pip install flawfinder` first')
        tmp.flush()
        os.system('open %s' % tmp.name)
        time.sleep(2)  # wait to open the file

