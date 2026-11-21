#!/usr/bin/env python3
"""Reference solver for LODESTAR.   python3 solve.py HOST PORT   (needs pycryptodome)

For each channel the unknown is the block integer m < B = 2^2040 and the lossy oracle answers
[ (f*m mod n) < B ]  (E2 = yes) for any multiplier f, flipped with probability 1/5.
Instead of voting on single comparisons, Narrow keeps a Bayesian posterior over m (a list of
intervals with weights), asks the multiplier whose answer is most informative about it and updates
exactly -- this works unchanged for the 2048-bit key and for the legacy key with n < 2B, where
the textbook interval-narrowing recipe does not apply.  Then: bespoke OAEP decode, OPEN, unseal.
"""
import hashlib, json, os, random, re, socket, sys, time, bisect, math
from Crypto.Cipher import AES

# ---------------- Bayesian narrowing of the Manger comb oracle (noisy) ----------------

class Narrow:
    NMAX = 700; CAP_EVAL = 40; CAP = 40; SPLIT_W = 0.0; PRUNE_W = 1e-11; HEAVY_W = 1e-3
    def __init__(s, n, e, C, B, eps, lo=1, hi=None, rng=None):
        s.n, s.e, s.C, s.B, s.eps = n, e, C, B, eps
        s.P = [[lo, hi if hi is not None else B, 1.0]]
        s.rng = rng or random.Random()
        s.q = 0
    # ---- posterior helpers
    def quantile(s, p):
        acc = 0.0
        for lo, hi, w in s.P:
            if acc + w >= p:
                fr = (p - acc) / w if w > 0 else 0.0
                return lo + (((hi - lo) * int(fr * (1 << 53))) >> 53)
            acc += w
        return s.P[-1][1] - 1
    def teeth(s, f, lo, hi, cap=3):
        """accepted sub-intervals of [lo,hi) for multiplier f ; None if too many teeth"""
        n, B = s.n, s.B
        i0 = (f * lo) // n
        i1 = (f * (hi - 1)) // n
        if i1 - i0 > cap:
            return None
        out = []
        for i in range(i0, i1 + 1):
            a = max(lo, -((-i * n) // f))
            b = min(hi, -((-(i * n + B)) // f))
            if b > a:
                out.append((a, b))
        return out
    def info_gain(s, f, core):
        """expected information (bits) about which piece holds m"""
        n, B, eps = s.n, s.B, s.eps
        def H(q):
            return 0.0 if q <= 0 or q >= 1 else -(q * math.log2(q) + (1 - q) * math.log2(1 - q))
        qbar, cond = 0.0, 0.0
        He = H(eps)
        for lo, hi, w in core:
            t = s.teeth(f, lo, hi, s.CAP_EVAL)
            if t is None:                      # comb too fine to represent: carries no usable information
                phi = B / n
                qi = phi * (1 - eps) + (1 - phi) * eps
                qbar += w * qi
                cond += w * H(qi)
            else:                              # exact: the answer is a noisy function of m itself
                phi = sum(b - a for a, b in t) / (hi - lo)
                qbar += w * (phi * (1 - eps) + (1 - phi) * eps)
                cond += w * He
        return H(qbar) - cond
    def p_accept(s, f, core):
        return s.info_gain(f, core)

    def choose(s):
        import math
        n, B, eps, rng = s.n, s.B, s.eps, s.rng
        P = s.P
        heavy = [pc for pc in P if pc[2] >= 2e-4] or P
        hm = sum(c[2] for c in heavy)
        core = [[a, b, w / hm] for a, b, w in heavy]
        Lc, Hc = max(s.quantile(0.01), 1), s.quantile(0.99)
        Hc = max(Hc, Lc + 1)
        acc, theta = 0.0, core[0][0]
        for lo, hi, w in core:
            if acc + w >= 0.5:
                theta = lo + (((hi - lo) * int(((0.5 - acc) / w) * (1 << 53))) >> 53)
                break
            acc += w
        Wd = Hc - Lc + 1
        cands = set()
        if Wd * 64 > Lc:
            cands.update(range(2, 20))
            lo2, hi2 = max(2, n // max(1, Hc + 1)), n // max(1, Lc) + 2
            for _ in range(60):
                cands.add(rng.randrange(lo2, hi2 + 1) if hi2 > lo2 else lo2)
            f_lo = max(2, B // Wd)
            for _ in range(40):
                cands.add(f_lo + rng.randrange(0, 2 * f_lo + 1))
        def fam(width, num_off, cover, count=24):
            if cover <= 0:
                return
            fmax = max(2, width // cover)
            imax = (fmax * theta) // n
            for _ in range(count):
                i = rng.randrange(max(0, imax // 3), imax + 1)
                cands.add(max(2, (i * n + num_off + theta // 2) // theta))
        fam(B, B, theta - Lc)
        fam(B, 0, Hc - theta)
        fam(n - B, n, theta - Lc)
        fam(n - B, B, Hc - theta)
        best, bf = -1.0, None
        for f in cands:
            h = s.info_gain(f, core)
            if h > best:
                best, bf = h, f
        if bf is None:
            bf = rng.randrange(2, 65)
        return bf
    def update(s, f, ans):
        eps = s.eps; n, B = s.n, s.B
        lin, lout = ((1 - eps), eps) if ans else (eps, 1 - eps)
        new = []
        for lo, hi, w in s.P:
            t = s.teeth(f, lo, hi, s.CAP if w >= s.HEAVY_W else 3) if w >= s.SPLIT_W else None
            if t is None:
                fa = B / n
                new.append([lo, hi, w * (fa * lin + (1 - fa) * lout)])
                continue
            pos = lo
            tot = hi - lo
            for a, b in t + [(hi, hi)]:
                if a > pos:
                    new.append([pos, a, w * ((a - pos) / tot) * lout])
                if b > a:
                    new.append([a, b, w * ((b - a) / tot) * lin])
                pos = max(pos, b)
        tot = sum(p[2] for p in new)
        mx = max(p[2] for p in new)
        P = [[a, b, w / tot] for a, b, w in new if w > s.PRUNE_W]
        P.sort(key=lambda p: p[0])
        # bound the piece count: merge the lightest piece into its lighter adjacent neighbour (mass kept)
        while len(P) > s.NMAX:
            i = min(range(len(P)), key=lambda k: P[k][2])
            cand = []
            if i > 0 and P[i - 1][1] == P[i][0]:
                cand.append(i - 1)
            if i + 1 < len(P) and P[i][1] == P[i + 1][0]:
                cand.append(i + 1)
            if not cand:
                P.pop(i)
                continue
            j = min(cand, key=lambda k: P[k][2])
            a, b = (j, i) if j < i else (i, j)
            P[a] = [P[a][0], P[b][1], P[a][2] + P[b][2]]
            del P[b]
        s.P = P
    def candidates(s, maxw=256):
        """integers inside the heaviest pieces, if those pieces are narrow enough to try exhaustively"""
        out, acc, size = [], 0.0, 0
        for lo, hi, w in sorted(s.P, key=lambda p: -p[2]):
            size += hi - lo
            if size > maxw:
                return None
            out.append((lo, hi))
            acc += w
            if acc >= 0.9:
                break
        return [m for lo, hi in out for m in range(max(1, lo - 2), hi + 2)]

def run(oracle, n, e, C, B, eps, maxq, rng=None, log=None, lo=1):
    rng = rng or random.Random()
    q = 0
    nr = Narrow(n, e, C, B, eps, lo=lo, rng=rng)
    nr.q = q
    while nr.q < maxq:
        f = nr.choose()
        a = oracle(f); nr.q += 1
        nr.update(f, a)
        if nr.q % 20 == 0:
            c = nr.candidates()
            if c is not None:
                for m in c:
                    if pow(m, e, n) == C:
                        return m, nr.q
        if log and nr.q % 500 == 0:
            log(nr.q, nr.quantile(0.001), nr.quantile(0.999), len(nr.P))
    return None, nr.q

# ---------------- relay client + solver ----------------

K, HLEN, B, EPS = 256, 32, 1 << 2040, 0.2
LABEL = b"LODESTAR/startracker/v1"


def mgf(seed, length):
    out, ctr = b"", 0
    while len(out) < length:
        out += hashlib.sha256(ctr.to_bytes(4, "big") + seed).digest()[::-1]
        ctr += 1
    return out[:length]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def unpad(m):
    em = m.to_bytes(K, "big")
    assert em[0] == 0
    seed = xor(em[1:1 + HLEN], mgf(em[1 + HLEN:], HLEN))
    db = xor(em[1 + HLEN:], mgf(seed, K - HLEN - 1))
    assert db[:HLEN] == hashlib.sha256(LABEL).digest()
    return db[db.index(b"\x01", HLEN) + 1:]

_ANSI = re.compile(rb"\x1b\[[0-9;]*m")
PROMPTS = ("\n  \u203a ".encode(), b"\n  > ")


def read_banner(f):
    """read the connect banner up to the first prompt (printed without a newline)"""
    buf = b""
    while not _ANSI.sub(b"", buf).endswith(PROMPTS):
        ch = f.read(1)
        if not ch:
            raise EOFError
        buf += ch


def clean(line):
    """strip the prompt prefix that precedes a reply on the same line"""
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return re.sub(r"^(\s*[\u203a>]\s*)+", "", line.strip()).strip()


class Relay:
    def __init__(self, host, port):
        self.f = socket.create_connection((host, port), timeout=120).makefile("rwb", buffering=0)
        read_banner(self.f)
        self.used = 0

    def cmd(self, line):
        self.f.write(line.encode() + b"\n")
        return clean(self.f.readline().decode("utf8", "replace"))


def solve(host, port, log=print):
    rl = Relay(host, port)
    P = json.loads(rl.cmd("PARAMS"))
    e, budget = P["e"], P["budget"]
    secrets_ = {}
    t0 = time.time()
    for ch in "AB":
        n, C = int(P[ch]["n"], 16), int(P[ch]["C"], 16)
        log(f"[*] channel {ch}: n/B = {n / B:.3f}")

        def oracle(f, ch=ch, n=n, C=C):
            r = rl.cmd(f"CHECK {ch} {C * pow(f, e, n) % n:x}")
            rl.used += 1
            if r not in ("E1", "E2"):
                raise RuntimeError(r)
            return r == "E2"

        m, q = run(oracle, n, e, C, B, EPS, budget - rl.used, rng=random.Random(),
                      log=lambda q, L, H, k: log(f"    {ch}: {q} queries, support 2^{(H - L).bit_length()}, {k} pieces, {time.time() - t0:.0f}s"))
        if m is None:
            log(f"[-] channel {ch}: not recovered within budget")
            return None
        log(f"[+] channel {ch}: block recovered after {q} queries (total {rl.used}/{budget})")
        secrets_[ch] = unpad(m)
    r = rl.cmd(f"OPEN {secrets_['A'].hex()} {secrets_['B'].hex()}")
    if not r.startswith("SEAL "):
        log("[-] OPEN:", r)
        return None
    blob = bytes.fromhex(r.split()[1])
    sa, sb = secrets_["A"], secrets_["B"]
    key = hashlib.sha256(b"LODESTAR-SEAL" + sa[::-1] + hashlib.sha256(sb).digest()[::-1]).digest()
    nonce = hashlib.sha256(b"LODESTAR-NONCE" + sa + sb).digest()[:12]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(blob[:-16], blob[-16:])


if __name__ == "__main__":
    out = solve(sys.argv[1], int(sys.argv[2]))
    print(out)
    sys.exit(0 if out else 1)
