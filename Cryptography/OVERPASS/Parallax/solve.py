#!/usr/bin/env python3
import hashlib, os, random, re, socket, sys, time
from fpylll import BKZ, IntegerMatrix, LLL, Pruning
from fpylll.fplll.bkz_param import Strategy
from Crypto.Cipher import AES

LEAK = 6
SHIFT = 256 - LEAK

_ANSI = re.compile(rb"\x1b\[[0-9;]*m")
PROMPTS = ("\n  \u203a ".encode(), b"\n  > ")


def read_banner(f):
    buf = b""
    while not _ANSI.sub(b"", buf).endswith(PROMPTS):
        ch = f.read(1)
        if not ch:
            raise EOFError
        buf += ch
    return _ANSI.sub(b"", buf).decode("utf8", "replace")


def clean(line):
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return re.sub(r"^(\s*[\u203a>]\s*)+", "", line.strip()).strip()


def be(n, ln=32):
    return n.to_bytes(ln, "big")


def chal(tag, t, msg, p):
    return int.from_bytes(hashlib.sha256(tag + be(t, 256) + msg).digest(), "big") % p


def strategies():
    try:
        BKZ.Param(block_size=40, strategies=BKZ.DEFAULT_STRATEGY)
        return BKZ.DEFAULT_STRATEGY
    except Exception:
        out = []
        for bs in range(101):
            if bs <= 20:
                out.append(Strategy(bs, [], []))
            else:
                out.append(Strategy(bs, [max(10, bs - 14)] if bs > 30 else [], [Pruning.LinearPruningParams(bs, 10)]))
        return out


def solve_xy(rows, p, X, Y, g, P, log, betas=(20, 30, 40, 45, 50, 55, 60), tmax=None):
    m = len(rows)
    W = 1 << SHIFT
    M = IntegerMatrix(m + 3, m + 1)
    T = []
    for i, (c1, c2, s1, a) in enumerate(rows):
        M[0, i] = (-c1) % p
        M[1, i] = c2 % p
        M[2 + i, i] = p
        T.append((a * W + W // 2 - s1) % p)
    for i in range(m):
        M[m + 2, i] = T[i]
    M[m + 2, m] = W // 2
    st = strategies()

    def check(A):
        for r in range(A.nrows):
            if abs(A[r, m]) != W // 2:
                continue
            sgn = 1 if A[r, m] == -(W // 2) else -1
            e = [sgn * A[r, i] for i in range(m)]
            if max(abs(v) for v in e) > W:
                continue
            s2 = [(T[i] + e[i] + rows[i][2]) % p for i in range(m)]
            d = [(s2[i] - rows[i][2]) % p for i in range(2)]
            det = (-rows[0][0] * rows[1][1] + rows[1][0] * rows[0][1]) % p
            if det == 0:
                continue

            inv = pow(det, -1, p)
            x = (d[0] * rows[1][1] - d[1] * rows[0][1]) * inv % p
            y = (rows[1][0] * d[0] - rows[0][0] * d[1]) * inv % p
            if pow(g, x, P) == X and pow(g, y, P) == Y:
                return x, y
        return None

    LLL.reduction(M)
    r = check(M)
    if r:
        return r + (0,)
    for beta in betas:
        t0 = time.time()
        BKZ.reduction(M, BKZ.Param(block_size=beta, strategies=st, flags=BKZ.AUTO_ABORT | BKZ.MAX_LOOPS, max_loops=12))
        r = check(M)
        log(f"    BKZ-{beta}: {'solved' if r else 'no'} ({time.time() - t0:.0f}s)")
        if r:
            return r + (beta,)
    return None


def solve(host, port, log=print):
    s = socket.create_connection((host, port), timeout=60)
    f = s.makefile("rwb", buffering=0)
    par = {}
    for k, v in re.findall(r"^(\w+) = (\S+)$", read_banner(f), re.M):
        par[k] = int(v, 16) if v.startswith("0x") else int(v)
    P, g, p, X, Y, mx = (par[k] for k in ("P", "g", "p", "X", "Y", "MAX_SIGN"))

    def cmd(line):
        f.write(line.encode() + b"\n")
        return clean(f.readline().decode("utf8", "replace")).split()

    rows = []
    for _ in range(mx):
        msg = os.urandom(16)
        _, t, s1, z = cmd("SIGN " + msg.hex())
        t, s1, z = int(t, 16), int(s1, 16), int(z)
        rows.append((chal(b"range", t, msg, p), chal(b"doppler", t, msg, p), s1, z))
    log(f"[*] collected {len(rows)} signatures")
    res = solve_xy(rows, p, X, Y, g, P, log)
    if not res:
        log("[-] lattice did not recover (x, y)")
        return None
    x, y = res[:2]
    log("[+] (x, y) recovered and checked against X, Y")
    msg = bytes.fromhex(cmd("UNLOCK")[1])
    k = random.randrange(1, p)
    t = pow(g, k, P)
    s1 = (k + chal(b"range", t, msg, p) * x) % p
    s2 = (k + chal(b"doppler", t, msg, p) * y) % p
    r = cmd(f"PROVE {t:#x} {s1:#x} {s2:#x}")
    if r[0] != "SEAL":
        log("[-] PROVE:", r)
        return None
    key = hashlib.sha256(be(y) + be(x)).digest()[::-1]
    nonce = hashlib.sha256(be(x * y % p)).digest()[:12]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(bytes.fromhex(r[1]), bytes.fromhex(r[2]))


if __name__ == "__main__":
    out = solve(sys.argv[1], int(sys.argv[2]))
    print(out)
    sys.exit(0 if out else 1)
