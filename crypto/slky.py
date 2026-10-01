"""slky 哈希算法与有符号数学工具。"""
from __future__ import annotations
import hashlib
from functools import lru_cache
from typing import Optional

def to_signed(value: int) -> int:
    return value if value < 128 else value - 256


def signed_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero")
    if (a < 0) != (b < 0) and a % b != 0:
        return a // b + 1
    return a // b


def signed_mod(a: int, b: int) -> int:
    return a - signed_div(a, b) * b

@lru_cache(maxsize=300000)
def _slky_cached(input_bytes: bytes, secondary_bytes: bytes, post_key: Optional[bytes]) -> bytes:
    if not input_bytes:
        raise ValueError("slky input is empty")
    n = len(input_bytes)
    first_byte = to_signed(input_bytes[0])
    last_byte = to_signed(input_bytes[n - 1])
    signed_sum = sum(to_signed(b) for b in input_bytes) + n
    avg = signed_div(signed_sum, n)
    seed = signed_div(signed_sum + last_byte * first_byte, n)
    remainder = signed_mod(signed_sum, n)

    work = bytearray(input_bytes)
    work.extend(str(seed).encode("ascii"))
    if secondary_bytes:
        work.extend(secondary_bytes)
        remainder = (remainder + len(secondary_bytes)) & 0xFF

    avg_byte = avg & 0xFF
    for i, value in enumerate(work):
        work[i] = value ^ avg_byte

    digest = bytearray(hashlib.md5(bytes(work)).digest())
    digest_len = len(digest)
    v64 = ((digest_len // 2) + remainder) & 0xFF

    for pos in range(digest_len):
        current = digest[pos]
        swap_idx = abs(to_signed(current)) % digest_len
        if swap_idx > digest_len // 2:
            current = (current ^ v64) & 0xFF
            digest[pos] = current
        target = digest[swap_idx]
        digest[swap_idx] = current
        if post_key:
            digest[pos] = (target ^ post_key[pos % len(post_key)]) & 0xFF
        else:
            digest[pos] = target & 0xFF
    return bytes(digest)


def slky(input_bytes: bytes, secondary_bytes: Optional[bytes], post_key: Optional[bytes]) -> bytes:
    return _slky_cached(bytes(input_bytes), bytes(secondary_bytes or b""), post_key)
