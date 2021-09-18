# Byte-at-a-time ECB decryption (Harder)

import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
if str(DIR.parent) not in sys.path:
    sys.path.insert(0, str(DIR.parent))
__package__ = DIR.name

from Crypto.Cipher import AES
from .set2.s2c11 import random_aes_key, random_bytes
from .set2.s2c9 import pkcs7_padding
import base64
from random import randint

key = random_aes_key()
cipher = AES.new(key, AES.MODE_ECB)

def encryption_oracle(random_prefix: bytes, plaintext1: bytes, plaintext2: bytes, block_size: int) -> bytes:
    plaintext_len = len(random_prefix) + len(plaintext1) + len(plaintext2)
    return cipher.encrypt(pkcs7_padding(random_prefix + plaintext1 + plaintext2, plaintext_len + block_size - plaintext_len % block_size))

def byte_by_byte_ecb_decryption_hard(unknown_plaintext: bytes) -> bytes:
    block_size = 16
    random_prefix = random_bytes(randint(1, 1000))
    bytes_to_add = block_size - len(random_prefix) % block_size
    if bytes_to_add == block_size:
        bytes_to_add = 0
    index_offset = bytes_to_add + len(random_prefix)
    plaintext = b'a' * (block_size - 1)
    # build byte by byte
    for idx in range(len(unknown_plaintext)):
        encryption_dict = {}
        attacker_chosen = b'a' * bytes_to_add + plaintext[idx:idx+block_size-1]
        for i in range(256):
            candidate = attacker_chosen + bytes([i])
            value = encryption_oracle(random_prefix, candidate, unknown_plaintext, block_size)[index_offset:block_size+index_offset]
            encryption_dict[value] = i
        block_number = (idx + index_offset) // block_size
        left_ind = block_number * block_size
        right_ind = (block_number + 1) * block_size
        byte_to_add = encryption_dict[encryption_oracle(random_prefix, b'a'*(bytes_to_add + block_size-idx%block_size-1), unknown_plaintext, block_size)[left_ind:right_ind]]
        plaintext += bytes([byte_to_add])
    return plaintext[(block_size - 1):]

def main() -> None:
    encoded_plaintext = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    with open("s2c14_out.txt", "w") as f:
        decoded_plaintext = base64.b64decode(encoded_plaintext)
        f.write(f"decrypted message:\n {byte_by_byte_ecb_decryption_hard(decoded_plaintext).decode()}")
        f.write(f"\nexpected message:\n {decoded_plaintext.decode()}")

if __name__ == "__main__":
    main()