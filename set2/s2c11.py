# An ECB/CBC detection oracle

import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
if str(DIR.parent) not in sys.path:
    sys.path.insert(0, str(DIR.parent))
__package__ = DIR.name

from Crypto.Cipher import AES
from random import randint
from .set1.set1 import ecb_score
from .set2.s2c9 import pkcs7_padding
from .set2.s2c10 import encrypt_in_cbc

def random_bytes(length: int) -> bytes:
    """
    Generate random byte string with specified length.
    """
    return bytes([randint(0, 255) for _ in range(length)])

def random_aes_key(length: int = 16) -> bytes:
    """
    Generate random AES key 
    """
    return random_bytes(length)

def encryption_oracle(plaintext: bytes) -> bytes:
    """
    Oracle that performs AES encryption under CBC mode half the time, ECB mode the other half of the time.
    """
    key = random_aes_key()
    plaintext = random_bytes(randint(5, 10)) + plaintext + random_bytes(randint(5, 10))
    plaintext = pkcs7_padding(plaintext, len(plaintext) + 16 - len(plaintext) % 16)
    print("Expected: ", end='')
    if randint(0, 1):
        cipher = AES.new(key, AES.MODE_ECB)
        print("ECB")
        return cipher.encrypt(plaintext)
    else:
        print("CBC")
        return encrypt_in_cbc(plaintext, key, random_bytes(len(key)))

def detection_oracle(plaintext: bytes) -> str:
    """
    Assumes a black box that might be encrypting AES-128 in ECB or CBC mode. Prints which encryption mode is happening.
    """
    ciphertext = encryption_oracle(plaintext)
    return "CBC" if ecb_score(ciphertext) == 1 else "ECB"

def main() -> None:
    plaintext = b'a' * 600
    print(f"Actual: {detection_oracle(plaintext)}")

if __name__ == "__main__": 
    main()