#!/usr/bin/env python3
import hashlib, hmac, os, random, re, socket, sys


P = 65537
N = 24


def coef(r, c):
    return [int.from_bytes(hashlib.sha256(b"vigil/a|%d|%d|%d" % (r, c, i)).digest()[:8], "big") % P for i in range(N)]

M64 = (1 << 64) - 1
ROUNDS = 10


def _sbox():

    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = (a << 1) ^ (0x11B if a & 0x80 else 0)
            b >>= 1
        return r
    inv = [0] + [next(y for y in range(1, 256) if mul(x, y) == 1) for x in range(1, 256)]
    out = []
    for x in range(256):
        b = inv[x]
        s = b ^ ((b << 1) | (b >> 7)) & 0xFF ^ ((b << 2) | (b >> 6)) & 0xFF ^ ((b << 3) | (b >> 5)) & 0xFF ^ ((b << 4) | (b >> 4)) & 0xFF ^ 0x63
        out.append(s & 0xFF)
    return out


SBOX = _sbox()
PERM = [0, 5, 2, 7, 4, 1, 6, 3]


def xtime(a):
    return ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else a << 1


def mix_col(c):
    a0, a1, a2, a3 = c
    return [xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
            a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
            xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)]


def F(r, k):
    x = (r ^ k).to_bytes(8, "big")
    y = [SBOX[b] for b in x]
    y = [y[PERM[i]] for i in range(8)]
    z = mix_col(y[:4]) + mix_col(y[4:])
    return int.from_bytes(bytes(z), "big")


def encrypt(pt, round_keys):
    L, R = pt >> 64, pt & M64
    for k in round_keys:
        L, R = R, L ^ F(R, k)
    return (L << 64) | R


P, N, G = 65537, 24, 16
FAULT_CAP = int(os.environ.get('VIGIL_CAP', '950'))
V_TOP = int(os.environ.get('V_TOP', '3'))
V_LEAD = int(os.environ.get('V_LEAD', '2'))
BATCH = int(os.environ.get('BATCH', '6'))


def coef(r, c):
    return [int.from_bytes(hashlib.sha256(b"vigil/a|%d|%d|%d" % (r, c, i)).digest()[:8], "big") % P for i in range(N)]


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r


INVMC = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def linv(z):
    b = z.to_bytes(8, "big")
    y = []
    for half in (b[:4], b[4:]):
        y += [gmul(INVMC[i][0], half[0]) ^ gmul(INVMC[i][1], half[1]) ^ gmul(INVMC[i][2], half[2]) ^ gmul(INVMC[i][3], half[3]) for i in range(4)]
    out = [0] * 8
    for i in range(8):
        out[PERM[i]] = y[i]
    return out


def hkdf(salt, ikm, info, ln=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < ln:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:ln]


def solve_linear(rows, ncols):
    A = [r[0][:] + [r[1]] for r in rows]
    piv, ri = [], 0
    for c in range(ncols):
        p = next((i for i in range(ri, len(A)) if A[i][c] % P), None)
        if p is None:
            continue
        A[ri], A[p] = A[p], A[ri]
        inv = pow(A[ri][c], -1, P)
        A[ri] = [x * inv % P for x in A[ri]]
        for i in range(len(A)):
            if i != ri and A[i][c] % P:
                f = A[i][c]
                A[i] = [(x - f * y) % P for x, y in zip(A[i], A[ri])]
        piv.append(c)
        ri += 1
    if any(all(x == 0 for x in r[:-1]) and r[-1] % P for r in A):
        return False, {}
    free = [c for c in range(ncols) if c not in piv]
    sol = {}
    for k, c in enumerate(piv):
        if all(A[k][f] % P == 0 for f in free if f != c):
            sol[c] = A[k][-1]
    return True, sol

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


class Relay:
    def __init__(self, host, port):
        self.f = socket.create_connection((host, port), timeout=120).makefile("rwb", buffering=0)
        read_banner(self.f)

    def batch(self, lines):
        self.f.write(b"".join(l.encode() + b"\n" for l in lines))
        return [clean(self.f.readline().decode("utf8", "replace")) for _ in lines]


def phase1(rl, log):
    cells = [(r, c) for r in range(16) for c in range(16)]
    random.shuffle(cells)
    cells = cells[:76]
    vals = [int(v) for v in rl.batch([f"SHARE {r} {c}" for r, c in cells])]
    for a in (1, 3, 5, 7):
        for b in (1, 3, 5, 7):
            rows = []
            for (r, c), v in zip(cells, vals):
                row = coef(r, c) + [0] * 48
                row[24 + r] = 1
                row[40 + c] = 1
                row[56 + (a * r + b * c) % G] = 1
                rows.append((row, v))
            ok, sol = solve_linear(rows, 72)
            if ok and all(i in sol for i in range(24)):
                log(f"[+] ledger: diagonal index = ({a}r+{b}c) mod 16, s recovered from {len(cells)} cells")
                return [sol[i] for i in range(24)]
    return None


def phase2(rl, log):
    rks = {}
    used = 0
    for rnd in range(ROUNDS, 0, -1):
        votes = [[0] * 256 for _ in range(8)]
        accepted = 0
        done = False
        while not done and used < FAULT_CAP:
            pts = [random.getrandbits(128) for _ in range(min(BATCH, FAULT_CAP - used))]
            if not pts:
                break
            res = rl.batch([f"FAULT {rnd} {p:032x}" for p in pts])
            used += len(pts)
            for rep in res:
                c, f = (int(x, 16) for x in rep.split())
                def peel(x):
                    L, R = x >> 64, x & M64
                    for j in range(ROUNDS, rnd, -1):
                        L, R = R ^ F(L, rks[j]), L
                    return L, R
                (L, R), (L2, R2) = peel(c), peel(f)
                a, a2 = L.to_bytes(8, "big"), L2.to_bytes(8, "big")
                d = linv(R ^ R2)
                act = [i for i in range(8) if a[i] != a2[i]]
                if not act or [i for i in range(8) if d[i]] != act:
                    continue
                accepted += 1
                for i in act:
                    for k in range(256):
                        if SBOX[a[i] ^ k] ^ SBOX[a2[i] ^ k] == d[i]:
                            votes[i][k] += 1
            key, done = 0, True
            for i in range(8):
                order = sorted(range(256), key=lambda k: -votes[i][k])
                top, second = votes[i][order[0]], votes[i][order[1]]
                if top < V_TOP or top - second < V_LEAD:
                    done = False
                key = (key << 8) | order[0]
            if done:
                rks[rnd] = key
        if rnd not in rks:
            return None, used
        log(f"    round {rnd}: key recovered ({accepted} usable pairs, {used} FAULT queries so far)")
    return [rks[i] for i in range(1, ROUNDS + 1)], used


def solve(host, port, log=print):
    rl = Relay(host, port)
    s = phase1(rl, log)
    if s is None:
        log("[-] ledger inference failed")
        return None
    rks, used = phase2(rl, log)
    if rks is None:
        log("[-] DFA did not converge within the fault budget")
        return None
    pt = random.getrandbits(128)
    assert int(rl.batch([f"ENC {pt:032x}"])[0], 16) == encrypt(pt, rks), "round keys wrong"
    mk = hkdf(hashlib.sha256(b"".join(x.to_bytes(2, "big") for x in s)).digest(),
              b"".join(k.to_bytes(8, "big") for k in rks), b"vigil/mac/v2")
    msg0, tag0 = rl.batch(["SAMPLE"])[0].split()
    assert hmac.new(mk, msg0.encode(), hashlib.sha256).hexdigest() == tag0, "mac key wrong"
    gate = rl.batch(["GATE"])[0]
    r = rl.batch(["FORGE " + hmac.new(mk, gate.encode(), hashlib.sha256).hexdigest()])[0]
    log(f"[*] FAULT queries used: {used}")
    return r


if __name__ == "__main__":
    out = solve(sys.argv[1], int(sys.argv[2]))
    print(out)
    sys.exit(0 if out and out.startswith("RELEASE") else 1)
