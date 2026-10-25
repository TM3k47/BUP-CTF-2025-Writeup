#!/usr/bin/env python3
"""BUP CTF 2025 - Digital Forensics - Clue Everywhere

firmware.bin hides an XOR-obfuscated ZIP between two marker strings.
The key "moonlight" is the word visible in clue.png.
After running this, unzip secret.zip and read secret.txt.
"""
key = b"moonlight"
BEGIN = b"---BEGIN_ID_DAT---"
END = b"---END_ID_DAT---"

with open("firmware.bin", "rb") as f:
    data = f.read()

start = data.find(BEGIN) + len(BEGIN)
end = data.find(END)
obf_data = data[start:end].strip()

decoded = bytearray(b ^ key[i % len(key)] for i, b in enumerate(obf_data))

with open("secret.zip", "wb") as f:
    f.write(decoded)

print("Decoded ZIP saved as secret.zip")
