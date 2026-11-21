# Trust Me Bro — author README (INTERNAL: contains the real flag, never ship)

Flag: `OVERPASS{th3_0r4cl3_l13s_but_truth_l34ks}`  (server/flag.txt)

## Layout
`dist/` player files (chall.py, output.txt, README.txt) · `server/` service + Docker · `solve/` reference solver,
decoder, whitebox shortcut tests · `tools/` key generation and packaging · `writeup.md` full solution.

## Scheme
RSA-2048, e = 65537, key fixed per deployment (`server/secret.py`), fresh `m` per connection.
`c = m^e`, `enc_flag = flag XOR SHAKE256(m)`. The relay answers one bit per hex ciphertext line:
`parity(c'^d mod n)` XOR `distort(session, c')`. Budget 12,000 answers, 900 s, malformed lines uncharged.

`distort` (private, not in dist/):
* **keyed sticky lies** — a fixed 15 % of ciphertexts (HMAC of the exact ciphertext under a per-session key)
  are answered wrongly, *always the same way*: repeating a query never averages the lie away;
* **class inversion** — a hidden per-session mask inverts the answer for 8 of the 16 residues of `q mod 16`,
  so un-calibrated answers on random ciphertexts carry no information at all.

## Why it is Insane (and not the old challenge)
The old oracle (i.i.d. 15 % noise, 20,000 queries) fell to a tuned per-bit vote. Here:
1. Repetition is useless, so the 2048 doubling bits `b_i` of `r = m/n` cannot be voted on individually
   (best uncoded single-shot accuracy is 0.86, ~290 wrong bits, unrepairable — `solve/shortcut_tests.py`).
2. Redundancy exists only *across multipliers*: for even `K`, `parity(K*m mod n) = floor(K*r) mod 2`, so
   `K = 2^(t+1)*h` is a function of the bit window starting at `t+1`; different `h` give independent lies about
   the same window => a non-adaptive convolutional code that must be modelled and decoded.
3. The class-inversion mask must be found first (known-plaintext calibration) or everything looks like noise.
4. Budget: BSC(0.15) capacity 0.390 bit/query => information floor 5,252 queries for ~2,049 bits. A practical
   decoder (window 14 forward-backward + spending extra queries only where the posterior is uncertain) needs
   ~10.1-10.5k including 336 calibration queries. 12,000 leaves ~15 % slack; 9,000 fails.

## Verification (this machine)
* `solve/solve.py` (live, real server): 3/3 flags at 10,483 / 10,277 / 10,270 queries; with a 9,000 budget 0/2.
* `solve/shortcut_tests.py`: 25 repeats of one ciphertext give 25 identical answers; textbook doubling attack
  raw accuracy 0.47; with the mask known 0.86 (~292 wrong bits of 2048).
* Server-side pow per query ~15 ms: a full live solve takes ~3.5 min; pipelining is allowed.

## Run
`python3 tools/gen_key.py` (new key) · `PORT=1337 python3 server/server.py` · `python3 solve/solve.py HOST PORT`
Deploy: `cd server && docker compose up -d --build` (remove the `FLAG` env line to serve `flag.txt`).

## Service UI
House style from `../common/ui.py` (copy in `server/ui.py`): framed banner, theme VIOLET, plain data lines via `ui.raw`, prompt `  › ` before each command, uniform `  ! bad input`. Colour is off by default (socket); set `ZUCTF_FORCE_COLOR=1` for themed colour, `ZUCTF_ASCII=1` for ASCII frames. No `debug_note` canary is used: the earlier brief removed every flag-shaped decoy.
