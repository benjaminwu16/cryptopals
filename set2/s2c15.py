# PKCS#7 padding validation
import doctest

def pkcs7_padding_validation(plaintext: bytes) -> bytes:
    """
    Takes in a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
    >>> pkcs7_padding_validation(b'ICE ICE BABY\x04\x04\x04\x04')
    b'ICE ICE BABY'
    >>> pkcs7_padding_validation(b'ICE ICE BABY\x01\x02\x03\x04')
    Traceback (most recent call last):
    Exception: invalid PKCS#7 padding
    >>> pkcs7_padding_validation(b'ICE ICE BABY\x05\x05\x05\x05')
    Traceback (most recent call last):
    Exception: invalid PKCS#7 padding
    """
    num_padding_bytes = plaintext[-1]
    if num_padding_bytes > len(plaintext):
        raise Exception('invalid PKCS#7 padding')

    if plaintext[-num_padding_bytes:] != bytes([num_padding_bytes]) * num_padding_bytes:
        raise Exception('invalid PKCS#7 padding')
    
    return plaintext[:-num_padding_bytes]

def main() -> None:
    doctest.testmod()

if __name__ == "__main__":
    main()