# Parallax — Writeup

**CTF:** Overpass · **Round:** Qualification · **Category:** Crypto · **Difficulty:** Medium
**Flag:** dynamic (differs per instance, format `OVERPASS{...}`)
**Solver:** [`solve.py`](solve.py)

---

## 1. Challenge explanation

> The Parallax beacon countersigns every range request with a second, lower-precision doppler report. It will seal its logbook for a station that can sign as the beacon.

The service is a Schnorr-signature beacon over a 2048-bit prime `P`, with a 256-bit prime `p = 2^256 - 189` dividing `P - 1` and a generator `g` of the order-`p` subgroup. On connect it prints `P, g, p, X, Y` and `MAX_SIGN`.

It holds **two secret keys**, fresh per connection:

- range key `x`, public `X = g^x`
- doppler key `y`, public `Y = g^y`

`SIGN <msg>` draws one fresh nonce `k` and publishes **one commitment `t = g^k` shared by both reports**:

```
c_r = SHA256("range"   || t || msg) mod p      s_r = k + c_r·x  mod p     (given in full)
c_d = SHA256("doppler" || t || msg) mod p      s_d = k + c_d·y  mod p     (only the top 6 bits z are given)
```

Reply: `SIG t s_r z` where `z` is the 6 most significant bits of the 256-bit `s_d`. At most `MAX_SIGN` requests.

To get the flag we must `UNLOCK` a fresh notice and `PROVE` — i.e. produce a valid range *and* doppler signature on that notice, which means knowing **both `x` and `y`**. The flag is AES-256-GCM encrypted under a key derived from `x` and `y`, so recovering the keys also decrypts the flag.

The weakness: the **same nonce `k` is reused** in both signatures, and the doppler response leaks 6 bits. That is a two-unknown *Hidden Number Problem*.

---

## 2. Step 1 — Eliminate the nonce

All of `t`, `c_r`, `c_d` are public, and `s_r` is known, so `k` can be removed by subtracting:

```
s_d − s_r = −c_r·x + c_d·y   (mod p)
```

`s_d` itself is unknown, but we know its top 6 bits: `s_d = z·2^250 + δ` with `0 <= δ < 2^250`. So each signature gives one equation in the two unknowns `x, y`, with an error of at most `2^250`.

Information count: each sample gives about 6 bits, and `x, y` are 512 unknown bits. With **110 samples** we have 660 bits ≥ 512, so the solution is unique in principle, but it is not easy to find. LLL alone fails.

## 3. Step 2 — Lattice (two-unknown HNP)

Let `W = 2^250` and `T_i = z_i·W + W/2 − s_r,i` (centering the unknown part). Use the basis rows (`m + 3` rows, `m + 1` columns for `m` samples):

```
( -c_r,i )_i   | 0
(  c_d,i )_i   | 0
( p·e_i  )     | 0          for each i
(  T_i   )_i   | W/2
```

The combination `x·row1 + y·row2 + Σ(...)·p·e_i + 1·row_T` gives a vector whose entries are `δ_i − W/2` (each at most `W/2` in size) with last coordinate `W/2` — a **very short vector** compared with the lattice determinant. Reduce the lattice with BKZ and look for it.

Practical notes:

- LLL and BKZ-20 return spurious short vectors that look right but are not.
- With 110 samples, **BKZ with block size 30–40** finds the real one.
- From a candidate vector read `s_d,i = T_i + e_i + s_r,i`, solve the 2×2 linear system for `(x, y)` on two samples, then **verify `g^x == X` and `g^y == Y`**. This is the only reliable stop test, because many rows look plausible.

## 4. Step 3 — Forge and unseal

1. `UNLOCK` → notice `msg`.
2. Pick any `k'`, set `t = g^k'`, compute `c_r, c_d` on the notice, then `s_r = k' + c_r·x`, `s_d = k' + c_d·y`.
3. `PROVE t s_r s_d` → `SEAL ct tag`.
4. Decrypt:

```
key   = reverse_bytes( SHA256( be32(y) || be32(x) ) )
nonce = SHA256( be32( x·y mod p ) )[:12]
AES-256-GCM(key, nonce)  ->  OVERPASS{...}        # dynamic flag
```

Captured run (not reusable, fresh keys on every connection):

```
collected 110 signatures
BKZ-20: no (2s)   BKZ-30: no (4s)   BKZ-40: solved (73s)
(x, y) recovered and checked against X, Y
OVERPASS{...}   <- dynamic flag, redacted
```

## 5. Usage

```bash
pip install fpylll pycryptodome
python3 solve.py HOST PORT
```

## Takeaways

- Reusing one nonce across two signatures (even under different keys) links them, and a *partial* leak of one response turns the pair into a Hidden Number Problem.
- Count the information: 6 bits × 110 samples ≈ 660 bits against 512 unknown bits is enough, and the lattice, once reduced strongly enough, finds the answer.
- Use an exact public check (`g^x == X`, `g^y == Y`) to stop the lattice search, since spurious short vectors are common.
