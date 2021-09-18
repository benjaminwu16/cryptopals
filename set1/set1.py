import doctest
import codecs
import base64
import typing
from Crypto.Cipher import AES

from collections import Counter

# utils
english_letter_frequencies = [ 
                0.08167, 0.01492, 0.02782, 0.04253, 0.12702, #A-E
                0.02228, 0.02015, 0.06094, 0.06094, 0.00153, #F-J
                0.00772, 0.04025, 0.02406, 0.06749, 0.07507, #K-O
                0.01929, 0.00095, 0.05987, 0.06327, 0.09056, #P-T
                0.02758, 0.00978, 0.0236, 0.0015, 0.01974, #U-W
                0.00074, 0.13 #Z, space
            ]

# 1.1
def hex_to_b64(encoded: str) -> str:
    """
    Converts string from hex to base64

    >>> s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    >>> hex_to_b64(s)
    'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    hex_rep = codecs.decode(encoded, 'hex')
    return codecs.encode(hex_rep, 'base64')[:-1].decode()

# 1.2
def str_xor(s1: str, s2: str) -> str:
    """
    Computes the xor of two hex strings
    
    >>> s1 = '1c0111001f010100061a024b53535009181c'
    >>> s2 = '686974207468652062756c6c277320657965'
    >>> str_xor(s1, s2)
    '746865206b696420646f6e277420706c6179'
    """
    return ''.join([hex(int(c1, 16) ^ int(c2, 16))[-1] for c1, c2 in zip(s1, s2)])

def xor(s1: bytes, s2: bytes) -> bytes:
    """
    Computes the xor of two byte strings.
    """
    return bytes([c1^c2 for c1, c2 in zip(s1, s2)])

# 1.3
def score_english_similarity(plaintext: bytes) -> float:
    """
    Computes the score of a given text with relation to frequencies of english letters
    """
    letter_counts = Counter(plaintext.lower())
    score = 0
    for i in range(97, 123):
        score += (letter_counts[i]) * english_letter_frequencies[i-97]
    score += letter_counts[32] * english_letter_frequencies[26] 
    return score

def single_byte_xor_cipher(ciphertext: bytes) -> typing.Tuple[bytes, bytes, bytes]:
    """
    Given ciphertext string XOR'd by one character, finds the character and decrypts the message
    """
    candidates = [(bytes([i]), bytes([i^c for c in ciphertext]), ciphertext) for i in range(256)]
    return max(candidates, key=lambda t: score_english_similarity(t[1]))

# 1.4
def single_char_xor_detection() -> None:
    """
    Detects which string in "s1c4_in.txt" is ciphertext by single-char XOR. Outputs result to "s1c4_out.txt"
    """
    with open("s1c4_in.txt") as f:
        decrypted = max((single_byte_xor_cipher(bytes.fromhex(line.rstrip())) for line in f), key=lambda t: score_english_similarity(t[1]))

# 1.5
def repeating_key_xor(s: bytes, key: bytes, hexify: bool = True) -> bytes:
    r"""
    applies repeating key xor encryption to a given string

    >>> s = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    >>> repeating_key_xor(s, b'ICE')
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    ciphertext = b''
    for index, c in enumerate(s):
        ciphertext += bytes([key[index%len(key)]^c])
    return ciphertext.hex() if hexify else ciphertext
    
# 1.6
def hamming_distance(s1: bytes, s2: bytes) -> bytes:
    """
    Computes the hamming distances between the bits of two strings 
    >>> s1 = b"this is a test"
    >>> s2 = b"wokka wokka!!!"
    >>> hamming_distance(s1, s2)
    37
    """
    return sum(bin(c1^c2).count('1') for c1, c2 in zip(s1, s2))

def find_repeated_key(text: bytes, key_size: int) -> bytes:
    """
    Given ciphertext and key_size, find the repeated key used for repeated key XOR
    """
    key = b''
    for start in range(key_size):
        result = single_byte_xor_cipher(text[start::key_size])
        key += result[0]
    return key

def break_repeating_key_xor(ciphertext: bytes) -> typing.Tuple[bytes, bytes]:
    """
    Decrypt a file which was ciphertext with repeating key XOR
    """
    distance_mappings = {}
    for key_size in range(2, 41):
        t = 0
        index = 0
        distances = []
        while True:
            if (index+2)*key_size >= len(ciphertext):
                break
            first_block = ciphertext[index*key_size:(index+1)*key_size]
            second_block = ciphertext[(index+1)*key_size:(index+2)*key_size]
            distances.append(hamming_distance(first_block, second_block) / key_size) 
            index += 2
        distance_mappings[key_size] = sum(distances) / len(distances)
    key_size = sorted(distance_mappings.items(), key=lambda t: t[1])[0][0]
    repeated_key = find_repeated_key(ciphertext, key_size)
    decrypted = repeating_key_xor(ciphertext, repeated_key, False)
    return decrypted, repeated_key    

# 1.7
def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> typing.Tuple[bytes, bytes]:
    """
    Decrypt a text encrypted via AES-128 in ECB mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# 1.8
def ecb_score(ciphertext: bytes, block_size: int = 16) -> int:
    """
    Returns the highest number of occurrences for a repeated block in a ciphertext. 
    This determines if the ciphertext was encrypted in ECB mode.
    """
    consecutive_counts = {}
    for idx in range(0, len(ciphertext), block_size):
        consecutive_counts[ciphertext[idx:idx+block_size]] = consecutive_counts.get(ciphertext[idx:idx+block_size], 0) + 1
    return max(consecutive_counts.values())

def detect_ecb_mode(ciphertext_list: typing.List[str]) -> bytes:
    """
    Given a list of hex-encoded encrypted strings, detect which one has been encrypted in ECB mode. 
    """
    return max(ciphertext_list, key=lambda ciphertext: ecb_score(codecs.decode(ciphertext, 'hex')))

def main() -> None:
    doctest.testmod()

if __name__ == '__main__':
    main()