#!/usr/bin/env python3
"""Whitebox checks that the old cheap paths no longer work.   python3 shortcut_tests.py"""
import math, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "server"))
import server as S

n, e = S.n, S.e
s = S.Session()
m = s.m

# T1: repeating one ciphertext never averages the distortion away
q = s.c * pow(2, e, n) % n
rep = [s.ask(q) for _ in range(25)]
print("T1 25 repeats of one query ->", "".join(map(str, rep)), "(all identical: voting is useless)",
      "PASS" if len(set(rep)) == 1 else "FAIL")

# T2: textbook parity-oracle bit-by-bit attack (one query per bit, 2^i doubling)
bits_ok = 0; N = 400
for i in range(1, N + 1):
    q = s.c * pow(2 ** i, e, n) % n
    truth = ((m << i) // n) & 1
    bits_ok += (s.ask(q) == truth)
print(f"T2 textbook doubling attack, raw per-bit accuracy over {N} bits: {bits_ok / N:.2f} (0.5 = no signal)",
      "PASS" if abs(bits_ok / N - 0.5) < 0.1 else "FAIL")

# T3: same attack if the inversion mask were known (best case without coding)
ok = 0
for i in range(1, N + 1):
    q = s.c * pow(2 ** i, e, n) % n
    truth = ((m << i) // n) & 1
    ok += ((s.ask(q) ^ ((s.mask >> (q % 16)) & 1)) == truth)
acc = ok / N
print(f"T3 doubling attack with the mask known: bit accuracy {acc:.2f} -> ~{(1 - acc) * 2048:.0f} wrong bits of 2048 (cannot be repaired)",
      "PASS" if acc < 0.9 else "FAIL")

# T4: information count
p = S.RATE
H = -p * math.log2(p) - (1 - p) * math.log2(1 - p)
cap = 1 - H
print(f"T4 BSC({p}) capacity {cap:.3f} bit/query -> floor {2049 / cap:.0f} queries; budget {S.BUDGET}; "
      f"reference solver uses ~10.1k incl. 336 calibration")
