#!/usr/bin/env python3
"""BUP CTF 2025 - OSINT - Find me

Decodes the faint string printed at the bottom of the BUP CTF poster.
Pure-Python Base92 decoder (no dependencies); dCode's Base92 tool gives the same result.
"""
ALPHABET = "!" + "".join(map(chr, range(35, 96))) + "".join(map(chr, range(97, 126)))
INDEX = {c: i for i, c in enumerate(ALPHABET)}


def base92_decode(s):
    bits = ""
    for i in range(0, len(s) - 1, 2):
        bits += format(INDEX[s[i]] * 91 + INDEX[s[i + 1]], "013b")
    if len(s) % 2:
        bits += format(INDEX[s[-1]], "06b")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))


print(base92_decode("9?]k&a.Eb[XAntiq=uv9g0cF:XX<nu663#S4]A*P0!").decode())
