# Hollow Vigil — Writeup

**CTF:** Overpass · **Round:** Qualification · **Category:** Crypto · **Difficulty:** Hard
**Flag:** dynamic (differs per instance, format `OVERPASS{...}`)
**Solver:** [`solve.py`](solve.py)

---

## 1. Challenge explanation

> The night-watch relay keeps a ledger, a block cipher and a signing key, and it leaks a little about each when asked.
> It releases its sealed notice only to someone who can sign it.

We get a service (`nc host port`) and the public part of the relay (`challenge.py`, protocol notes). Everything secret is drawn **per connection**.

The relay holds three secrets and combines them into one MAC key:

| Secret | What it is | How it leaks |
|---|---|---|
| Ledger `s` | 24 words mod 65537, plus three mask vectors `R`, `C`, `D` (16 words each) | `SHARE r c` returns `<coef(r,c), s> + R[r] + C[c] + D[g(r,c)]` mod 65537 |
| Round keys `rk_1..rk_10` | ten independent 64-bit keys of a 10-round Feistel cipher (AES S-box + byte transposition + MixColumns) | `ENC` (encrypt a block) and `FAULT r pt` (clean and *faulted* ciphertext) |
| MAC key | `HKDF-SHA256(salt = SHA256(s), ikm = rk_1 \|\| .. \|\| rk_10, info = "vigil/mac/v2")` | `SAMPLE` gives a signature of a fixed message, so a guess can be checked |

`GATE` prints the release notice. We must sign it with `HMAC-SHA256(mac_key, notice)` and send it with `FORGE`; the relay then prints the flag.
So the whole challenge is: **recover `s` from the ledger, recover all ten round keys from the fault oracle, rebuild the MAC key.**

Difficulty comes from the limits: the ledger gives only 76 cells, the fault oracle has a budget, `g(r,c)` is hidden, and the link sometimes damages a fault answer.

---

## 2. Phase 1 — Recover the ledger secret `s`

Each cell is **linear** over GF(65537) in the unknown vector `(s, R, C, D)` (24 + 16 + 16 + 16 = 72 unknowns):
the row is the public `coef(r,c)` followed by a one-hot in `R`, a one-hot in `C` and a one-hot in `D`.

The only unknown structure is the index of `D`: `g(r,c) = (a·r + b·c) mod 16`, with small odd `a`, `b` fixed per connection.
There are only 16 odd `(a,b)` pairs in `{1,3,5,7}`, so:

1. Request 76 random cells (random cells cover all `D` groups w.h.p.).
2. For each hypothesis `(a,b)`, build the 76 × 72 system and do Gaussian elimination mod 65537.
3. Only the true `(a,b)` gives a **consistent** system (76 equations > 70 effective unknowns; wrong hypotheses contradict themselves).
4. `s` is then determined (the two gauge directions only shift `R`/`C`/`D`, not `s`).

## 3. Phase 2 — Recover the ten round keys with Differential Fault Analysis

The cipher is a Feistel network: `L, R = R, L ^ F(R, k)`. `FAULT r` XORs a random non-zero pattern (one or two bytes) into the right half entering round `r`, and returns the clean and disturbed ciphertexts.

We attack from round 10 down to round 1. Assume all later round keys are already known:

1. **Peel** the later rounds off both ciphertexts: `(L, R) -> (R ^ F(L, k_j), L)`.
   Now the clean and faulty inputs `a`, `a'` to round `r`'s `F` are visible (they are the left halves), and `e = a ^ a'` is the injected pattern.
2. The output difference is `R_r ^ R'_r = F(a, k) ^ F(a', k)`. Undo MixColumns and the byte transposition (both are linear and public):
   `d_i = S(a_i ^ k_i) ^ S(a'_i ^ k_i)` for each byte `i`.
3. **Filter**: keep a pair only if the non-zero bytes of `d` are exactly the active bytes of `e`. This removes pairs where the link damaged an answer, and most no-op faults.
4. **Vote**: for each active byte, every key byte `k` that satisfies the S-box equation gets a vote (about 2 candidates per pair). The true key byte is in every pair, so it accumulates votes.
5. Accept a key byte when `top >= 3` votes and `lead >= 2` over the runner-up, then move to round `r-1`.

This needs roughly 60–90 fault queries per round, about 570–820 in total. Verify the recovered keys against `ENC`.

## 4. Phase 3 — Release

```
mac_key = HKDF-SHA256(salt = SHA256(s_0 || .. || s_23, 2 bytes each, big-endian),
                      ikm  = rk_1 || .. || rk_10 (8 bytes each, big-endian),
                      info = "vigil/mac/v2", length = 32)
```

1. Check `mac_key` against the `SAMPLE` signature (so a wrong key is caught without spending the single `FORGE`).
2. `GATE` → notice. Compute `HMAC-SHA256(mac_key, notice)`.
3. `FORGE <hex>` → the relay prints the flag.

Captured run (not reusable, every connection has new secrets):

```
ledger: diagonal index = (1r+1c) mod 16, s recovered from 76 cells
round 10: key recovered (40 usable pairs, 60 FAULT queries so far)
...
FAULT queries used: 612
RELEASE OVERPASS{...}   <- dynamic flag, redacted
```

## 5. Usage

```bash
python3 solve.py HOST PORT        # standalone, only needs the Python standard library
```

## Takeaways

- A "linear leak with a hidden index" is solved by trying every hypothesis for the index and keeping the consistent one.
- A Feistel cipher with independent round keys is still broken by DFA: peel known rounds, then the S-box difference equation gives a handful of key candidates per fault.
- Checking a candidate key against a known signature (`SAMPLE`) before the one-shot action avoids wasting the only attempt.
