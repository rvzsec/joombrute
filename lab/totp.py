#!/usr/bin/env python3
"""
Compute the current 6-digit TOTP code from a base32 secret. Used inside
docker (a one-liner via `docker exec`) so the host machine never sees the
secret either. Pure-stdlib, no pip install required.

Usage:
    python3 lab/totp.py [BASE32_SECRET]

Default secret matches lab/seed_mfa.php.
"""
import base64
import hmac
import hashlib
import struct
import sys
import time

def totp(secret_b32: str, period: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"

if __name__ == "__main__":
    secret = sys.argv[1] if len(sys.argv) > 1 else "JBSWY3DPEHPK3PXP"
    print(totp(secret))
