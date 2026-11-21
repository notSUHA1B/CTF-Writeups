#!/usr/bin/env python3
# TRUST ME BRO -- handout copy of the relay. The distortion module is private
# to the relay and is not part of this handout.
import hashlib, secrets
from Crypto.Util.number import long_to_bytes

from secret import n, d           # n is published in output.txt, d is not
FLAG = open("flag.txt", "rb").read().strip()

e = 65537
BUDGET = 12000


def new_session():
    m = secrets.randbelow(n - 2) + 2
    c = pow(m, e, n)
    key = hashlib.shake_256(long_to_bytes(m, 256)).digest(len(FLAG))
    enc_flag = bytes(a ^ b for a, b in zip(FLAG, key))
    return m, c, enc_flag


def answer(session, q):
    """One line in, one bit out. `q` is a ciphertext (taken mod n)."""
    q %= n
    x = pow(q, d, n)
    return (x & 1) ^ distort(session, q)       # distort(): private to the relay

# Wire protocol: on connect the relay prints a framed banner, then the plain lines
#   c = <hex>   enc_flag = <hex>   budget = <int>
# and a prompt ("  > " or its arrow form, no trailing newline) before every command. For every hex line
# received it answers one line, 0 or 1. Anything else gets "  ! bad input" and is not counted.
# After BUDGET answers it closes the connection. HELP shows the banner, QUIT disconnects.
