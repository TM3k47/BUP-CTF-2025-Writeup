#!/usr/bin/env python3
"""BUP CTF 2025 - Crypto - Riddle Lock

The riddle's answer ("sunrise") is the passphrase. The AES key is SHA-256(passphrase)
and ciphertext.bin is laid out as: nonce (12 bytes) | tag (16 bytes) | ciphertext.
Requires: pip install pycryptodome
"""
from hashlib import sha256
from Crypto.Cipher import AES

passphrase = "sunrise"  # 7-letter answer to the riddle
key = sha256(passphrase.encode()).digest()

with open("ciphertext.bin", "rb") as f:
    data = f.read()

nonce, tag, ciphertext = data[:12], data[12:28], data[28:]

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print("Decrypted flag:", plaintext.decode())
