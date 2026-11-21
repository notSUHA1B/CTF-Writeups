#!/usr/bin/env python3
"""Reference solver for TRUST ME BRO.   python3 solve.py HOST PORT [path/to/output.txt]   (needs pycryptodome, numpy)

Model (see writeup.md):  for even K the relay's parity bit of (K*m mod n) is
floor(K*r) mod 2 with r = m/n.  K = 2^(t+1)*h gives [frac(h*u_t) >= 1/2], u_t = 0.b_{t+1}b_{t+2}...
(bits of r).  Lies are keyed per exact ciphertext (no averaging), so redundancy has to come from
different h at the same scale t: the queries form a convolutional code over the bits of r.
Stages: 1) calibrate the hidden q mod 16 inversion mask with known plaintexts,
2) non-adaptive first pass, 3) forward-backward decoding, 4) spend the remaining budget only on
uncertain positions, 5) verify pow(m,e,n)==c and decrypt.
"""
import hashlib, os, random, re, socket, sys
import numpy as np
from Crypto.Util.number import long_to_bytes

# ---------------- forward-backward decoder for the convolutional code ----------------
def G(x): 
    f=np.floor(x); return f*0.5+np.maximum(0.0,(x-f)-0.5)
def p1_table(W,h):
    w=np.arange(1<<W,dtype=np.float64); a=h*w/(1<<W); L=h/(1<<W)
    return (G(a+L)-G(a))/L
class Dec:
    def __init__(s,W,eps,pool):
        s.W=W; s.eps=eps; s.pool=pool
        s.P1={h:p1_table(W,h) for h in pool}
    def loglik(s,obs_t):
        # obs_t: list of (h,bit) at scale t -> log P(obs | window) over 2^W windows
        m=np.zeros(1<<s.W); e=s.eps
        for h,b in obs_t:
            p=s.P1[h]*(1-e)+(1-s.P1[h])*e
            m+=np.log(p if b else 1-p)
        return m
    def posterior(s,obs,nbits):
        """obs: dict t -> list[(h,bit)]. bits indexed 0..nbits-1 ; scale t covers bits t..t+W-1 (window oldest..newest)."""
        W=s.W; S=1<<(W-1)
        M=[None]*nbits
        for i in range(nbits):
            t=i-(W-1)
            M[i]=s.loglik(obs[t]) if (t>=0 and t in obs and obs[t]) else np.zeros(1<<W)
        wins=np.arange(1<<W)
        def lse2(a,b):
            mx=np.maximum(a,b); return mx+np.log(np.exp(a-mx)+np.exp(b-mx))
        alpha=np.zeros((nbits+1,S),dtype=np.float32); alpha[0]=-np.log(S)
        for i in range(nbits):
            c=alpha[i][wins>>1]+M[i]
            a=lse2(c[:S],c[S:]); a-=a.max(); alpha[i+1]=a
        beta=np.zeros((nbits+1,S),dtype=np.float32)
        for i in range(nbits-1,-1,-1):
            c=M[i]+beta[i+1][wins&(S-1)]            # per window, to be summed over oldest bit? sum over windows with same prev state
            # prev state = w>>1 ; two windows per prev state: w=2*sp+b
            c2=c.reshape(S,2)
            b_=lse2(c2[:,0],c2[:,1]); b_-=b_.max(); beta[i]=b_
        llr=np.zeros(nbits)
        for i in range(nbits):
            c=alpha[i][wins>>1]+M[i]+beta[i+1][wins&(S-1)]
            odd=c[1::2]; even=c[0::2]
            mo=odd.max(); me=even.max()
            llr[i]=(mo+np.log(np.exp(odd-mo).sum()))-(me+np.log(np.exp(even-me).sum()))
        return llr

# ---------------- relay client + solver ----------------

W = 14
EPS = 0.15
NB = 2052                       # bits of r = m/n to recover (n < 2^2047)
POOL = [1, 5, 23, 61, 113, 201, 331, 419, 7, 47, 89, 157, 263, 383, 17, 71, 139, 223, 307, 449, 3, 29, 97, 181]
R0 = 3
CAL_PER_CLASS = 21

_ANSI = re.compile(rb"\x1b\[[0-9;]*m")
PROMPTS = ("\n  \u203a ".encode(), b"\n  > ")


def read_banner(f):
    """read the connect banner + plain data lines up to the first prompt (printed without newline)"""
    buf = b""
    while not _ANSI.sub(b"", buf).endswith(PROMPTS):
        ch = f.read(1)
        if not ch:
            raise EOFError
        buf += ch
    return _ANSI.sub(b"", buf).decode("utf8", "replace")


def clean(line):
    """strip the prompt prefix that precedes a reply on the same line"""
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return re.sub(r"^(\s*[\u203a>]\s*)+", "", line.strip()).strip()


class Relay:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=60)
        self.f = self.s.makefile("rwb", buffering=0)
        txt = read_banner(self.f)
        self.c = int(re.search(r"^c = ([0-9a-f]+)$", txt, re.M).group(1), 16)
        self.enc = bytes.fromhex(re.search(r"^enc_flag = ([0-9a-f]*)$", txt, re.M).group(1))
        self.budget = int(re.search(r"^budget = (\d+)$", txt, re.M).group(1))
        self.used = 0

    def batch(self, qs, chunk=1500):
        out = []
        for i in range(0, len(qs), chunk):
            part = qs[i:i + chunk]
            # sendall: an unbuffered makefile().write() does a single send() and can drop the tail
            self.s.sendall(b"".join(b"%x\n" % q for q in part))
            for _ in part:
                line = self.f.readline()
                if not line:
                    raise EOFError(f"relay closed the connection after {self.used + len(out) - i} replies")
                out.append(int(clean(line.decode("utf8", "replace"))))
            self.used += len(part)
        return out


def solve(host, port, n, log=print):
    e = 65537
    rl = Relay(host, port)
    c = rl.c
    log(f"[*] budget {rl.budget}")

    # stage 1: known-plaintext calibration of the q mod 16 inversion mask
    need = {k: [] for k in range(16)}
    plan = []
    while any(len(v) < CAL_PER_CLASS for v in need.values()):
        a = random.randrange(2, n)
        q = pow(a, e, n)
        if len(need[q % 16]) < CAL_PER_CLASS:
            need[q % 16].append((q, a & 1))
            plan.append((q, a & 1))
    ans = rl.batch([q for q, _ in plan])
    votes = {k: 0 for k in range(16)}
    for (q, par), r in zip(plan, ans):
        votes[q % 16] += 1 if (r ^ par) else -1
    L = {k: int(votes[k] > 0) for k in range(16)}
    log(f"[+] inversion mask learned from {len(plan)} queries: {sum(L.values())} of 16 classes inverted")

    # stage 2-4: coded queries
    total_bits = NB + W - 1
    dec = Dec(W, EPS, POOL)
    obs = {t: [] for t in range(NB)}
    nxt = {t: 0 for t in range(NB)}

    def run(pairs):
        qs = []
        for t, h in pairs:
            K = (1 << (t + 1)) * h
            qs.append(c * pow(K % n, e, n) % n)
        res = rl.batch(qs)
        for (t, h), q, r in zip(pairs, qs, res):
            obs[t].append((h, r ^ ((_mask >> (q % 16)) & 1)))

    _mask = sum(L[k] << k for k in range(16))
    run([(t, POOL[k]) for t in range(NB) for k in range(R0)])
    for t in range(NB):
        nxt[t] = R0
    thr = 8.0
    for rnd in range(40):
        llr = dec.posterior(obs, total_bits)
        B = 0
        for i in range(NB):
            B = (B << 1) | (1 if llr[i] > 0 else 0)
        for cand in (((n * B) >> NB) + k for k in (0, 1, -1, 2, -2)):
            if 1 < cand < n and pow(cand, e, n) == c:
                log(f"[+] m verified after {rl.used} queries (round {rnd})")
                key = hashlib.shake_256(long_to_bytes(cand, 256)).digest(len(rl.enc))
                return bytes(a ^ b for a, b in zip(rl.enc, key))
        unc = [i for i in range(NB) if abs(llr[i]) < thr]
        log(f"    round {rnd}: {rl.used} queries, {len(unc)} uncertain bits")
        need_t = set()
        for i in unc:
            need_t.update(range(max(0, i - W + 1), min(i, NB - 1) + 1))
        pairs = [(t, POOL[nxt[t]]) for t in sorted(need_t) if nxt[t] < len(POOL)]
        for t, _ in pairs:
            nxt[t] += 1
        if not pairs:
            thr += 4.0
            continue
        pairs = pairs[:rl.budget - rl.used]
        if not pairs:
            break
        run(pairs)
    return None


if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "output.txt")
    n = int(re.search(r"n = (\d+)", open(path).read()).group(1))
    f = solve(host, port, n)
    print(f)
    sys.exit(0 if f else 1)
