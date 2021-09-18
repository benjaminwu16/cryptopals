# Implement PKCS#7 padding
import doctest

def pkcs7_padding(block: bytes, desired_length: int) -> bytes:
    r"""
    Pads irregularly-sized block to a desired length
    >>> pkcs7_padding(b'YELLOW SUBMARINE', 20)
    b'YELLOW SUBMARINE\x04\x04\x04\x04'
    """
    num_to_add = max(0, desired_length - len(block))
    return block + bytes([num_to_add]) * num_to_add

if __name__ == "__main__":
    doctest.testmod()