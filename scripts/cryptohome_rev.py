#!/usr/bin/env python3
"""BUP CTF 2025 - Reverse - Cryptohome

The binary transforms the 34-character input, XORs it with the repeating key
"xor_is_fun" and compares it against 34 bytes stored at offset 0x82d60.
Undoing the XOR gives an Atbash-encoded string; undoing Atbash gives the flag.
"""

# 34 target bytes from the hexdump at offset 0x82d60
target = bytes.fromhex("212939072e2624024601205f3c0936146f39323d2e30166f003c2839191b27262422")
key = b"xor_is_fun"

# Step 1: reverse the XOR
xored = "".join(chr(b ^ key[i % len(key)]) for i, b in enumerate(target))
print("After XOR:   ", xored)  # YFKXGU{...}


# Step 2: reverse the Atbash substitution (a<->z, b<->y, ...)
def atbash(c):
    if "a" <= c <= "z":
        return chr(ord("z") - (ord(c) - ord("a")))
    if "A" <= c <= "Z":
        return chr(ord("Z") - (ord(c) - ord("A")))
    return c


print("After Atbash:", "".join(atbash(c) for c in xored))
