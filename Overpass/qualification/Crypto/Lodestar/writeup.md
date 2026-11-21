# Lodestar — Writeup

**CTF:** Overpass · **Round:** Qualification · **Category:** Crypto · **Difficulty:** Insane
**Flag:** dynamic (differs per instance, format `OVERPASS{...}`)
**Solver:** [`solve.py`](solve.py)

---

## 1. Challenge explanation

> The LODESTAR relay keeps two sealed star fixes on two keys. It will tell any ground station how a decryption attempt failed — over a lossy link. Name both fixes and it unseals its flight logbook.

Every connection is a fresh session with two RSA channels, both with `e = 65537`:

- **Channel A**: a standard 2048-bit modulus.
- **Channel B**: a "legacy" modulus only slightly larger than `2^2040` (between `1.5·B` and `1.95·B`, with `B = 2^2040`).

Each channel holds one 32-byte secret ("star fix") `S_a` / `S_b`, wrapped in an **OAEP-like encoding** (custom MGF: SHA-256 digests with the bytes *reversed*) and encrypted with RSA. The sealed blocks are given to us.

Commands:

- `CHECK <A|B> <hex>` — the relay decrypts our ciphertext and returns only an error class: **E1** if the first octet is not `0x00`, **E2** otherwise (a later check failed). This is a **Manger-style padding oracle**. The reply is flipped with probability **1/5** (lossy link), independently for each reply. Budget: 40000 replies shared by both channels.
- `OPEN <S_a> <S_b>` — at most 8 attempts. If both are right, the relay returns `AES-GCM("LOGBOOK: " + flag)` under a key derived from both secrets.

So the goal: break **both** RSA ciphertexts using a noisy Manger oracle, decode the OAEP blocks to get `S_a`, `S_b`, then derive the AES key.

Why it is hard:

1. Manger's attack is sequential and assumes a perfect oracle; with 20 % noise any committed decision may be wrong.
2. Channel B has `B < n < 2B`, which breaks the precondition of Manger's step 2 (see below), so the textbook recipe fails even without noise.
3. The budget is finite: 40000 queries for two 2040-bit unknowns.

---

## 2. Step 1 — The oracle in one formula

Let `m` be the encoded block integer (`m < B` because the first octet is `0x00`). Send `c' = C · f^e mod n` for a multiplier `f` of our choice. The relay decrypts it to `x = f·m mod n`, and says E1 iff `x >= B` (first octet non-zero). So

```
E2  <=>  (f·m mod n) < B        (then flipped with probability 0.2)
```

for any integer `f` we pick. The threshold `B` is public and fixed; we cannot put a *known* plaintext under it.

## 3. Step 2 — Why textbook Manger fails

- **Channel A** (`n >> 2B`): Manger's steps 1–3 work (with a perfect oracle).
- **Channel B** (`B < n < 2B`): the accepted set `[0, B)` is almost all of `Z_n`, so the "find `f` such that `f·m` lands in `[B, 2B)`" step cannot be done as in the paper. The recipe returns garbage even with a clean oracle.
- **Noise**: Manger narrows the interval one committed decision at a time; with a 20 % flip rate a single wrong answer destroys everything. Simple voting wastes the budget.

## 4. Step 3 — Noise-optimal Bayesian narrowing

Instead of committing to decisions, keep a **posterior over `m`**: a list of intervals with weights (initially `[1, B)` uniform).

For a multiplier `f`, the accepted set is a *comb*:

```
union_i [ ceil(i·n / f), ceil((i·n + B) / f) )
```

Inside one posterior interval only a few teeth matter, so the exact big-integer edges can be computed and the interval split. For `n < 2B` the rejected gap `[(i·n + B)/f, (i+1)·n/f)` plays the role of the tooth.

Each query:

1. **Choose `f`** from candidate families — small multipliers, and `f ≈ i·n/θ` or `(i·n + B)/θ` so that a tooth edge sits on the posterior median `θ` — and pick the one with the **maximum expected information gain** `H(mixture) − Σ w_i · H(answer | piece i)`.
2. **Update** with the likelihoods `(1−ε)` / `ε` for every piece (split pieces at the tooth edges).
3. **Bound** the list at 700 pieces by merging the lightest adjacent pieces. The mass is kept, so a truth that was wrongly down-weighted can recover.
4. Every 20 queries, test the integers in the heaviest narrow pieces with `pow(m, e, n) == C`. This is the exact verifier: a success is certain.

Progress is about 0.27 bit/query, essentially the channel capacity of a binary symmetric channel with `ε = 0.2` (`1 − H(0.2) ≈ 0.28`). This is why it fits in the budget.

The same code works unchanged for both channels.

## 5. Step 4 — Decode OAEP, open, unseal

For each recovered `m`:

```
EM       = m.to_bytes(256, 'big')            # first byte must be 0
seed     = maskedSeed ^ MGF(maskedDB, 32)
DB       = maskedDB   ^ MGF(seed, 223)
check DB[:32] == SHA256("LODESTAR/startracker/v1")
S        = DB[index of 0x01 + 1:]            # the 32-byte secret
```

(`MGF` here uses SHA-256 blocks with each 32-byte digest **reversed**.)

Then `OPEN S_a S_b` returns `ciphertext || tag`, decrypted with:

```
key   = SHA256("LODESTAR-SEAL" || reverse(S_a) || reverse(SHA256(S_b)))
nonce = SHA256("LODESTAR-NONCE" || S_a || S_b)[:12]
AES-256-GCM  ->  "LOGBOOK: OVERPASS{...}"        # dynamic flag
```

## 6. Usage

```bash
pip install pycryptodome
python3 solve.py HOST PORT
```

## Takeaways

- A noisy oracle is best handled with Bayesian inference over the secret rather than by committing to bit-by-bit decisions; ask the query with maximal expected information.
- Always read the key sizes: `B < n < 2B` quietly invalidates a textbook attack's precondition.
- Keep an exact verifier (`pow(m, e, n) == C`) so approximate inference can never produce a wrong answer.
