# Trust Me Bro

**Category:** Crypto · **Difficulty:** Insane · **Flag format:** `OVERPASS{...}` · **Instance:** `nc <host> <port>`

> The relay will decrypt anything you hand it and tell you one thing about the result.
> It also tells you it is honest. It is not.

Files: `chall.py`, `output.txt`, `README.txt` (the `dist/` folder). Every connection is a fresh session
with its own secret; the flag is sealed under that secret.
