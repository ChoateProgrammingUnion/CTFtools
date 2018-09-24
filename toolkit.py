import pwn, re, math, binascii,warnings


def repr_to_bytes(repr: str, base: int = None, endian='big') -> bytes:
    s=re.sub(r'\s','',repr).lower()
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
        warnings.warn('No explicit base specified. Decoded %s using base %d'%(repr,base))
    n=int(s,base)
    return n.to_bytes(int(math.ceil(math.log2(n)//8)+1),endian)

def repr_to_str(repr: str, base: int = None, endian='big') -> str:
    return repr_to_bytes(repr,base,endian).decode('latin1',)

def hex_to_bytes(repr:str,endian='big'):
    return repr_to_bytes(repr,16,endian)

def hex_to_str(repr:str,endian='big') -> str:
    return repr_to_str(repr,16,endian)

def decimal_to_bytes(repr:str,endian='big')-> bytes:
    return repr_to_bytes(repr,10,endian)

def decimal_to_str(repr:str,endian='big')-> str:
    return repr_to_str(repr,10,endian)

def binary_to_bytes(repr:str,endian='big')-> bytes:
    return repr_to_bytes(repr,2,endian)

def binary_to_str(repr:str,endian='big')-> str:
    return repr_to_str(repr,2,endian)
