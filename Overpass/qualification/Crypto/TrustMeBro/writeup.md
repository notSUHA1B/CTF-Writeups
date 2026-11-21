# Trust Me Bro — writeup (INTERNAL)

All secrets (`m`, the lie key, the inversion mask) are per connection: re-derive everything each time.

## 1. Reduce the oracle
For a ciphertext `c' = c * K^e` the relay decrypts to `K*m mod n`. With `r = m/n`:
`parity(K*m mod n) = (K*m mod 2) XOR (floor(K*r) mod 2)`. For even `K = 2j`: `[frac(j*r) >= 1/2]`.
With `j = 2^t * h`: `[frac(h * u_t) >= 1/2]`, `u_t = frac(2^t r) = 0.b_{t+1} b_{t+2} ...`.
`h = 1` is the textbook doubling attack (bit `b_{t+1}`); other `h` are *different functions of the same bits*.

## 2. Notice the oracle is not i.i.d.
Asking the same ciphertext twice gives the same answer; random ciphertexts look 50/50 although a single known
plaintext query (`q = a^e`, parity of `a` known) is right 85 % of the time *only for some residues of q mod 16*.
Calibrate: for each class of `q mod 16` query ~21 known plaintexts, majority of (answer XOR parity(a)) gives
the inversion mask (336 queries). After correcting, every answer is right with probability 0.85, independent
across distinct ciphertexts.

## 3. Decode a convolutional code
Queries `(t, h)` for `t = 0..2051`, `h` in a pool of distinct small multipliers. Query `(t,h)` depends on bits
`t .. t+W-1` (W = 14; the tail beyond the window is modelled exactly by averaging over the unknown suffix).
Forward-backward over the 2^13 window states gives a log-likelihood ratio per bit.
First pass: 3 queries per `t` (6,156). Then iterate: every `t` whose window contains a bit with |LLR| < 8 gets one
more `h` (new distinct ciphertext = fresh lie); re-decode. Candidate `m = floor(n * B / 2^2052) + {0,±1,±2}` is
verified with `pow(m, e, n) == c`. Typically 3-4 rounds, 10.1-10.5k queries in total.

## 4. Flag
`key = SHAKE256(m.to_bytes(256, 'big'))[:len(enc_flag)]`, `flag = enc_flag XOR key`.

## Captured session (one run, not reusable)
`inversion mask learned from 336 queries: 8 of 16 classes inverted; round 0: 6492 queries, 1603 uncertain bits;
round 1: 8516, 664; m verified after 10086 queries` -> `OVERPASS{th3_0r4cl3_l13s_but_truth_l34ks}`.
