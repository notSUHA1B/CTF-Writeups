# Trust Me Bro — Writeup

**CTF:** Overpass · **Round:** Qualification · **Category:** Crypto · **Difficulty:** Hard
**Flag:** dynamic (differs per instance, format `OVERPASS{...}`)
**Solver:** [`solve.py`](solve.py)

---

## 1. Challenge explanation

> The relay will decrypt anything you hand it and tell you one thing about the result.
> It also tells you it is honest. It is not.

We get a service (`nc host port`) and the handout `chall.py` + `output.txt` (the RSA public key `n`, `e = 65537`).

On every connection the relay creates a fresh session:

- a random secret `m`, and its ciphertext `c = m^e mod n` (sent to us);
- the flag encrypted with a key derived from `m`:
  `key = SHAKE256(m as 256 bytes)`, `enc_flag = flag XOR key` (also sent to us);
- a **budget of 12000 queries**.

For each query the client sends a ciphertext `q` and gets back **one bit**:

```python
x = pow(q, d, n)            # RSA decryption
return (x & 1) ^ distort(session, q)   # parity of the plaintext, XOR a hidden "lie"
```

So this is the classic **RSA parity oracle**, except the oracle **lies**: `distort()` is private and flips the answer.
Goal: recover `m` (then `flag = enc_flag XOR SHAKE256(m)`).

Why it is hard:

1. The textbook parity attack needs about 2048 *perfectly correct* answers, adaptively. Here answers are noisy (about 15 % wrong).
2. The lies are **deterministic per ciphertext** — asking the same `q` again returns the same answer, so you cannot repeat and majority-vote.
3. The lie is **not uniform**: it depends on `q mod 16`, with a hidden mask of "inverted" residue classes.
4. The budget (12000) is only about 5.8 queries per bit, so the queries must be spent carefully.

---

## 2. Step 1 — Reduce the oracle to bits of `m/n`

Send `c' = c · K^e mod n`. The relay decrypts it to `K·m mod n`.
Let `r = m/n` in `[0,1)`. Then

```
parity(K·m mod n) = (K·m mod 2) XOR (floor(K·r) mod 2)
```

For even `K = 2j`, the first term vanishes, so the answer is `floor(j·r) mod 2 = [ frac(j·r) >= 1/2 ]`.
Write `j = 2^t · h` with `h` odd (or small):

```
answer = [ frac(h · u_t) >= 1/2 ],   u_t = frac(2^t · r) = 0.b_{t+1} b_{t+2} b_{t+3} ...
```

where `b_i` are the binary digits of `r`.

- `h = 1` is exactly the textbook doubling attack: the answer is the single bit `b_{t+1}`.
- Other `h` give *different functions of the same bits* (they depend on `b_{t+1}…` and a few following bits).

That gives us redundancy: we can ask many **different** ciphertexts (different `h`) that all carry information about the same position `t`, and each one is a fresh ciphertext, so each gets an independent lie.

## 3. Step 2 — Learn the lie pattern (calibration)

Asking the same ciphertext twice gives the same answer, and random ciphertexts look 50/50, so at first nothing looks wrong.
The trick is to use queries where we **know the true answer**: pick a random `a`, send `q = a^e mod n`; the true parity is `a & 1`.

Group these by `q mod 16`. For some residue classes the oracle is right about 85 % of the time and for others it is *inverted* (right about 15 %). Per class, take the majority of `answer XOR parity(a)` over about 21 samples (16 classes × 21 = **336 queries**). That gives an **inversion mask** (8 of 16 classes inverted in the captured run).
After un-inverting every answer by the mask, each answer is correct with probability about 0.85, independently for distinct ciphertexts.

## 4. Step 3 — Decode a convolutional code

Query `(t, h)` depends only on bits `t … t+W-1` of `r` (window `W = 14`; the tail beyond the window is modelled exactly by averaging over the unknown suffix). So the queries form a **convolutional code** over the bit string of `r`, with a binary symmetric channel (error 0.15).

Decoder (in `solve.py`, class `Dec`):

- Precompute, for each multiplier `h`, `P(answer = 1 | window)` for all `2^14` windows.
- Combine all observations at scale `t` into a log-likelihood over the window states.
- Run **forward–backward (BCJR)** over the `2^13` states to get a log-likelihood ratio (LLR) for each of the 2052 bits.

## 5. Step 4 — Spend the budget adaptively

1. First pass: 3 queries per `t` for `t = 0..2051` → 6156 queries.
2. Decode. Mark every bit with `|LLR| < 8` as uncertain.
3. For every `t` whose window touches an uncertain bit, send **one more** query with a new `h` from a pool of small distinct multipliers (a new ciphertext = a fresh independent lie).
4. Re-decode. Repeat (typically 3–4 rounds, about 10.1–10.5 k queries total, under the 12000 budget).

## 6. Step 5 — Verify and get the flag

Build `B` from the signs of the LLRs, the candidate is `m = floor(n·B / 2^2052) + {0, ±1, ±2}`.
Check `pow(m, e, n) == c` — this makes the result certain, no guessing.
Then:

```python
key  = SHAKE256(m.to_bytes(256, 'big')).digest(len(enc_flag))
flag = enc_flag XOR key
```

Captured run (not reusable, every connection has a new secret):

```
inversion mask learned from 336 queries: 8 of 16 classes inverted
round 0: 6492 queries, 1603 uncertain bits
round 1: 8516 queries, 664 uncertain bits
m verified after 10086 queries
OVERPASS{...}   <- dynamic flag, redacted
```

## 7. Usage

```bash
pip install pycryptodome numpy
python3 solve.py HOST PORT output.txt     # output.txt = the handout file that holds n
```

## Takeaways

- A lying oracle with **per-input deterministic** lies defeats repetition, but *distinct* queries that carry the same information turn the problem into error-correcting-code decoding.
- Calibrate hidden structure of the noise with queries whose answer you can compute yourself.
- Always keep a cheap verifier (`pow(m, e, n) == c`) so decoding errors never turn into wrong answers.
