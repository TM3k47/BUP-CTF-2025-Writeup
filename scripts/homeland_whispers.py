#!/usr/bin/env python3
"""BUP CTF 2025 - Crypto - A Homeland's Whispers

The key is SHA-256("<year>:<word>"). The year is a Bengali poet's birth year and the
word is a one-word Bengali song title, so a tiny wordlist is enough to brute-force it.
AES-GCM's authentication tag rejects every wrong key, so only the right one decrypts.
Requires: pip install pycryptodome
"""
from hashlib import sha256
from Crypto.Cipher import AES


def make_key(year, word):
    return sha256(f"{year}:{word}".encode()).digest()


with open("ciphertext.bin", "rb") as f:
    data = f.read()

# format: nonce (12) | tag (16) | ciphertext
nonce, tag, ciphertext = data[:12], data[12:28], data[28:]

years = ["1861", "1899"]  # Rabindranath Tagore, Kazi Nazrul Islam
words = ["ekla", "amar", "bidrohi", "bhromor", "sonar", "bangla"]

for y in years:
    for w in words:
        try:
            cipher = AES.new(make_key(y, w), AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ciphertext, tag).decode()
            if "BUPCTF{" in pt:
                print("SUCCESS:", y, w, "=>", pt)
        except ValueError:
            pass  # wrong key: tag check failed
