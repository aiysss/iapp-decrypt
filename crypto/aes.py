"""AES 加解密工具。"""
from __future__ import annotations
from Crypto.Cipher import AES

def cyclic_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty xor key")
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key[:16], AES.MODE_CBC, iv=key[:16])
    return cipher.decrypt(ciphertext)


def pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("invalid PKCS5 padding: empty buffer")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"invalid PKCS5 padding length: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS5 padding bytes")
    return data[:-pad_len]


def aes_cbc_then_xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not block aligned")
    stage = aes_cbc_decrypt(ciphertext, key)
    return cyclic_xor(pkcs5_unpad(stage), key)

def aes_cbc_decrypt_only(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not block aligned")
    return pkcs5_unpad(aes_cbc_decrypt(ciphertext, key))
