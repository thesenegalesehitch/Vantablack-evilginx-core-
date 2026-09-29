# api/crypto.py
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, key: bytes) -> str:
    """Encrypts data using AES-GCM and returns a base64 encoded string."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt(data_b64: str, key: bytes) -> bytes:
    """Decrypts a base64 encoded string using AES-GCM."""
    aesgcm = AESGCM(key)
    data = base64.b64decode(data_b64)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
