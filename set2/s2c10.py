# Implement CBC Mode

import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
if str(DIR.parent) not in sys.path:
    sys.path.insert(0, str(DIR.parent))
__package__ = DIR.name

from Crypto.Cipher import AES
import base64
from .set1.set1 import xor
from .set2.s2c9 import pkcs7_padding
    
def encrypt_in_cbc(plaintext: bytes, key: bytes, IV: bytes) -> bytes:
    """
    Implementation of CBC Mode "by hand" (blackboxes ECB mode, then use XOR)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    previous_block = IV
    ciphertext = b''
    for idx in range(0, len(plaintext), len(key)):
        current_block = pkcs7_padding(plaintext[idx:idx+len(key)], len(key))
        current_block = cipher.encrypt(xor(previous_block, current_block))
        ciphertext += current_block
        previous_block = current_block
    return ciphertext

def decrypt_in_cbc(ciphertext: bytes, key: bytes, IV: bytes) -> bytes:
    """
    Implementation of CBC Mode "by hand" (blackboxes ECB mode, then use XOR)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    previous_block = IV
    plaintext = b''
    for idx in range(0, len(ciphertext), len(key)):
        current_block = pkcs7_padding(ciphertext[idx:idx+len(key)], len(key))
        plaintext += xor(cipher.decrypt(current_block), previous_block)
        previous_block = current_block
    return plaintext

def main() -> None:
    ciphertext = base64.b64decode(open("s2c10_in.txt", "r").read())
    key = b'YELLOW SUBMARINE'
    IV = b'\x00' * len(key)
    plaintext = decrypt_in_cbc(ciphertext, key, IV)
    with open("s2c10_out.txt", "w") as f:
        f.write(f"decoded message:\n{plaintext.decode()}")

if __name__ == "__main__":
    main()