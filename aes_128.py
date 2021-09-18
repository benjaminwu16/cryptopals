import typing

def xor(s1: bytes, s2: bytes) -> bytes:
    """
    Computes the xor of two byte strings.
    """
    return bytes([c1^c2 for c1, c2 in zip(s1, s2)])

def left_shift(byte: int, shift: int, length: int = 8) -> int:
    """
    Helper function for the inverse sub-bytes procedure. Performs a left circular shift on the state.
    >>> bin(left_shift(57, 1, 6))
    '0b110011'
    """
    shift %= length
    return ((byte * (1 << shift)) % (1 << length)) | (byte >> (length - shift))


def bitlength(x: int) -> int:
    """
    Finds position of the most significant bit of x (0-indexed)
    """
    for i in range(9, -1, -1):
        if (1 << i) - 1 < x:
            return i
    return 0

log_table = [0] * 256
antilog_table = [0] * 256
generator = 3

def precompute_tables() -> None:
    """
    Precomputes the log and antilog tables for GF256.
    Uses generator of 3. antilog[x] = 3^x, and log[antilog[x]] = x
    """
    antilog_table[0] = antilog_table[255] = 1
    log_table[1] = 0
    for i in range(1, 255):
        t = antilog_table[i-1]
        t = (t << 1) ^ t # multiply by 0x03 in GF256
        if t > 0xff:
            t ^= 0x11b
        antilog_table[i] = t
        log_table[t] = i

def gf256_multiply(a: int, b: int) -> int:
    """
    Given a, b in GF(2^8), returns a * b.
    >>> gf256_multiply(0x02, 0x87)
    21
    """
    if a == 0 or b == 0:
        return 0
    return antilog_table[(log_table[a] + log_table[b]) % 255]

def gf256_inv(byte: int) -> int:
    """
    Finds the inverse of a binary integer in GF(2^8).
    >>> gf256_inv(2)
    141
    >>> gf256_inv(5)
    82
    """
    if byte == 0:
        return 0
    return antilog_table[255 - log_table[byte]]
    
def add_round_key(state: bytes, key: bytes) -> bytes:
    """
    The add-round-key (and also reverse add-round-key) method in AES-128 for decryption.
    """
    return xor(state, key)

def inv_mix_columns(state: bytes) -> bytes:
    """
    Inverts the mix-columns method in AES-128 for decryption.
    """
    coeffs = [0x0e, 0x0b, 0x0d, 0x09]
    new_state = b''
    for i in range(16):
        t = 0
        for j in range(4):
            t ^= gf256_multiply(coeffs[(4 + j - i%4) % 4], state[i - (i%4) + j])
        new_state += bytes([t])
    return new_state

def inv_shift_rows(state: bytes) -> bytes:
    """
    Inverts the shift-rows method in AES-128 for decryption.
    >>> inv_shift_rows(b'abcdefghijklmnop')
    b'ankhebolifcpmjgd'
    """
    new_state = b''
    for i in range(16):
        new_state += bytes([state[(16 + i - (i%4) * 4) % 16]])
    return new_state

def inv_sub_bytes(state: bytes) -> bytes:
    """
    Inverts the sub-bytes method in AES-128 for decryption.
    >>> inv_sub_bytes(bytes([255]))
    b'}'
    """
    new_state = b''
    for byte in state:
        byte = 5 ^ left_shift(byte, 1) ^ left_shift(byte, 3) ^ left_shift(byte, 6)
        byte = gf256_inv(byte)
        new_state += bytes([byte])
    return new_state

def decrypt_aes_128(ciphertext: bytes, key: bytes) -> typing.Tuple[bytes, bytes]:
    """
    Decrypt a text encrypted via AES-128 in ECB mode.
    """
    bits_to_rounds = {
        128: 10,
        192: 12,
        256: 14
    }

    num_key_bits = len(key) * 8
    assert(num_key_bits in bits_to_rounds) 

    # pad ciphertext so that its length is a multiple of 16
    ciphertext += b'\x00'
    while len(ciphertext)%len(key) != 0:
        ciphertext += b'\x00'
    decrypted = b''
    num_rounds = bits_to_rounds[num_key_bits]
    # perform AES-128 on each block
    for start in range(0, len(ciphertext), len(key)):
        block = ciphertext[start:start+len(key)]
        block = add_round_key(block, key)
        for _ in range(num_rounds-1):
            block = inv_sub_bytes(block)
            block = inv_shift_rows(block)
            block = inv_mix_columns(block)
            block = add_round_key(block, key)
        block = inv_shift_rows(block)
        block = inv_sub_bytes(block)
        block = add_round_key(block, key)
        decrypted += block
    return decrypted