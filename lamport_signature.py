import secrets
from hashlib import sha256
from typing import List

def hash(message: bytes) -> bytes:
    return sha256(message).digest()

def generate_secret_key() -> bytes:
    random_bytes = lambda: secrets.token_bytes(32)
    return [random_bytes() for _ in range(512)]

def public_key_from_secret_key(secret_key) -> List(bytes):
    raw_long_public_key = [hash(secret_key[i]) for i in range(512)]
    raw_long_public_key_bytes = b''.join(raw_long_public_key)
    return hash(raw_long_public_key_bytes)

def message_to_bin(message: bytes) -> List(int):
    assert len(message) == 32
    messageint = int.from_bytes(message, byteorder='big')
    return [messageint >> i & 1 for i in range(256)]

def sign(message, secret_key):
    binlist = message_to_bin(message)
    show_or_hide = [[True, False] if i == 0 else [False, True] for i in binlist]
    flat_show_or_hide = [item for sublist in show_or_hide for item in sublist]
    return [secret_key[i] if flat_show_or_hide[i] else hash(secret_key[i]) for i in range(512)]

def verify(message, signature, public_key):
    binlist = message_to_bin(message)
    show_or_hide = [[True, False] if i == 0 else [False, True] for i in binlist]
    flat_show_or_hide = [item for sublist in show_or_hide for item in sublist]
    return hash(b''.join([hash(signature[i]) if flat_show_or_hide[i] else signature[i] for i in range(512)])) == public_key
