# ECB cut-and-paste

import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
if str(DIR.parent) not in sys.path:
    sys.path.insert(0, str(DIR.parent))
__package__ = DIR.name

from Crypto.Cipher import AES
from .set2.s2c11 import random_aes_key
from .set2.s2c9 import pkcs7_padding

import base64
import doctest
from random import randint
import typing

def key_value_to_obj(key_value_str: bytes) -> dict:
    """
    Parse k=v string into an object

    >>> key_value_to_obj(b'foo=bar&baz=qux&zap=zazzle')
    {b'foo': b'bar', b'baz': b'qux', b'zap': b'zazzle'}
    """
    obj = {}
    for pair in key_value_str.split(b'&'):
        [key, value] = pair.split(b'=')
        obj[key] = value
    return obj

def profile_for(email: bytes, uid: int = 10) -> bytes:
    """
    Generate user profile information with uid and role given an email. Eat the metacharacters &, =. 

    >>> profile_for(b'foo@bar.com')
    b'email=foo@bar.com&uid=10&role=user'
    >>> profile_for(b'foo@bar.com&role=admin')
    b'email=foo@bar.comroleadmin&uid=10&role=user'
    """
    email = email.replace(b'&', b'')
    email = email.replace(b'=', b'')
    encoded_profile = f'email={email.decode()}&uid={uid}&role=user'.encode()
    return encoded_profile

def encrypt_user_profile(encoded_profile: bytes, key: bytes = None) -> typing.Tuple[bytes, bytes]:
    """
    Encrypts user profile using AES-128-ECB with a randomly generated key
    """
    if key is None:
        key = random_aes_key()
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pkcs7_padding(encoded_profile, len(encoded_profile) + 16 - len(encoded_profile) % 16)
    return key, cipher.encrypt(plaintext)

def decrypt_user_profile(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts user profile encrypted in AES-128-ECB. Converts resulting text to a user profile object. 
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return key_value_to_obj(cipher.decrypt(ciphertext))

def get_admin_profile() -> dict:
    """
    Creates an admin profile using only the profile_for function.
    """
    # get the 'email=...uid=...' ciphertext blocks
    email1 = b'f' + b'o' * 4 + b'@bar.com'
    key, ciphertext1 = encrypt_user_profile(profile_for(email1))

    # get the 'admin\x04\x04...' ciphertext block
    email2 = b'a' * 9 + b'@admin' + b'\x04' * 11
    key, ciphertext2 = encrypt_user_profile(profile_for(email2), key)

    # concatenate and decrypt
    admin_profile = decrypt_user_profile(key, ciphertext1[:32] + ciphertext2[16:32])

    # strip padding
    admin_profile[b'role'] = admin_profile[b'role'][:5]
    return admin_profile

def main() -> None:
    doctest.testmod()
    admin_profile = get_admin_profile()
    assert(admin_profile[b'role'] == b'admin')

if __name__ == "__main__":
    main()