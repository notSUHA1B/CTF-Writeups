#!/usr/bin/env python3
import json
import math
import os
import random
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_vp = os.path.join(HERE, 'vocab.json')
VOCAB = json.load(open(_vp, encoding='utf-8'))['tokens']
TID = {t: i for i, t in enumerate(VOCAB)}
CLOSER = '"}'
STR_FIRST = 7
WORDS = [t for t in VOCAB if re.match(r'^[a-z_.]+$', t)
         and t not in ('fn', 'path', 'read_doc', 'list_docs', 'export_report')]
CONTENT = [t for t in VOCAB if not t.startswith('"') and t not in ('fn', 'path')
           and all(ord(c) >= 0x20 for c in t)]
NEED = ['s"', ',"', '\\u006e"', ':"', '．．', '／', '.md"']
QUIET = False
WHY = []


def say(*a):
    if not QUIET:
        print(*a, flush=True)


ANSI = re.compile(rb'\x1b\[[0-9;]*[A-Za-z]')


class Remote:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=30)
        self.buf = b''
        self.queries = 0
        self.log = []
        self.until_prompt()
        self.s.sendall(b'solver\n')
        self.until_prompt()

    def until_prompt(self):
        while True:
            for mark in (b'\xe2\x80\xba ', b'> '):
                k = self.buf.find(mark)
                if k != -1 and (self.buf[k + len(mark):].strip() == b''):
                    out, self.buf = self.buf[:k], b''
                    return out.decode('utf-8', 'replace')
            d = self.s.recv(65536)
            if not d:
                raise EOFError
            self.buf = ANSI.sub(b'', self.buf + d)

    def cmd(self, line):
        self.s.sendall(line.encode() + b'\n')
        out = self.until_prompt()
        lines = [l for l in out.split('\n') if l.strip() != '']
        self.log.append((line.split(' ', 1)[0], line, lines))
        return lines

    def ask(self, prompt):
        self.queries += 1
        return parse_ask(self.cmd('ASK ' + prompt))

    def check(self, js):
        self.queries += 1
        return self.cmd('CHECK ' + js)


def parse_ask(lines):
    lines = [l.strip() for l in lines]
    i = lines.index('call')
    r = {'call': lines[i + 1], 'trace': [], 'verdict': None, 'result': []}
    j = lines.index('trace') + 1
    while lines[j] != 'verdict':
        parts = lines[j].split()
        r['trace'].append([(VOCAB[int(a)], float(b)) for a, b in
                           (p.split(':') for p in parts[1:])])
        j += 1
    r['verdict'] = lines[j + 1]
    if 'result' in lines:
        k = lines.index('result') + 1
        r['result'] = lines[k:lines.index('end', k)]
    return r


def rel_scores(trace):
    steps = trace[STR_FIRST:]
    Z = [None] * len(steps)
    if not steps or len(steps[-1]) < 2:
        return {}, None
    Z[-1] = -dict(steps[-1])[CLOSER]
    score = {}
    for _ in range(len(steps) + 1):
        for k in range(len(steps) - 1, -1, -1):
            if Z[k] is not None:
                for t, lp in steps[k]:
                    score.setdefault(t, lp + Z[k])
            else:
                for t, lp in steps[k]:
                    if t in score:
                        Z[k] = score[t] - lp
                        break
    floor = min(score.values()) if score else None
    return score, floor


def emitted(call):
    return call


class Est:

    def __init__(self):
        self.obs = []
        self.prior = {}
        self.base = {}
        self.W = {}

    def add(self, counts, r):
        y, floor = rel_scores(r['trace'])
        self.obs.append((dict(counts), y, floor))
        return y, floor

    def fit(self, toks, y0, f0, lam=0.6):
        for t in toks:
            rows = [(c, y[t]) for c, y, _ in self.obs if t in y and c]
            ws = sorted({w for w, tt in self.prior if tt == t})
            if t in y0:
                self.base[t] = y0[t]
            if not ws:
                if t not in y0:
                    self.base[t] = f0 - 1.0
                continue
            fixed = t in y0
            for _ in range(2):
                sol = self._ridge(rows, ws, t, lam, self.base[t] if fixed else None)
                if fixed:
                    break
                if sol[0] <= f0 - 0.05:
                    self.base[t] = sol[0]
                    break
                self.base[t], fixed = f0 - 0.05, True
            off = 0 if fixed else 1
            for i, w in enumerate(ws):
                self.W.setdefault(w, {})[t] = sol[i + off]

    def _ridge(self, rows, ws, t, lam, fixed_base):
        nb = 0 if fixed_base is not None else 1
        n = nb + len(ws)
        A = [[0.0] * n for _ in range(n)]
        b = [0.0] * n
        for c, yy in rows:
            x = ([1.0] if nb else []) + [c.get(w, 0) for w in ws]
            yy = yy - (fixed_base or 0.0)
            for i in range(n):
                b[i] += x[i] * yy
                for j in range(n):
                    A[i][j] += x[i] * x[j]
        if nb:
            A[0][0] += 0.05
            b[0] += 0.05 * -2.5
        for i, w in enumerate(ws):
            A[i + nb][i + nb] += lam
            b[i + nb] += lam * self.prior[(w, t)]
        return solve_lin(A, b)

    def params(self, floor=-4.0):
        base = {t: self.base.get(t, floor - 1.0) for t in CONTENT}
        return base, self.W


def solve_lin(A, b):
    n = len(b)
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c]))
        M[c], M[p] = M[p], M[c]
        if abs(M[c][c]) < 1e-12:
            continue
        for r in range(n):
            if r != c:
                f = M[r][c] / M[c][c]
                for k in range(c, n + 1):
                    M[r][k] -= f * M[c][k]
    return [M[i][n] / M[i][i] if abs(M[i][i]) > 1e-12 else 0.0 for i in range(n)]


def scores(base, W, counts):
    s = dict(base)
    for w, n in counts.items():
        for t, v in W.get(w, {}).items():
            if t in s:
                s[t] += n * v
    return s


def predict(base, W, counts):
    s = scores(base, W, counts)
    order = sorted(s, key=lambda t: (-s[t], TID[t]))
    return [t for t in order if s[t] > 0][:12]


def _suppressors(W, u, drivers):
    used = {d for ds in drivers.values() for d in ds}
    cs = [(v, w) for w, d in W.items() for tt, v in d.items()
          if tt == u and v < -0.25 and w not in used]
    return [(w, v) for v, w in sorted(cs)]


def plan(base, W, target, drivers, margin=0.45, cap=16, tries=40, seed=1):
    rng = random.Random(seed)
    thr = min(margin, 0.25)
    for attempt in range(tries):
        drv = {t: (drivers[t][0] if attempt == 0 else rng.choice(drivers[t]))
               for t in target}
        c = {}
        ok = False
        for _ in range(120):
            s = scores(base, W, c)
            changed = False
            for i in reversed(range(len(target))):
                t = target[i]
                need = (0.0 if i == len(target) - 1 else s[target[i + 1]]) + margin
                if s[t] < need:
                    w = drv[t]
                    g = W.get(w, {}).get(t, 0.0)
                    if g <= 0.2:
                        WHY.append(('weak', t, w, round(g, 2)))
                        break
                    c[w] = c.get(w, 0) + max(1, math.ceil((need - s[t]) / g))
                    changed = True
                    s = scores(base, W, c)

            bad = [u for u in s if u not in target and s[u] > -thr]
            for u in sorted(bad, key=lambda x: -s[x]):
                for w, v in _suppressors(W, u, drivers):
                    c[w] = c.get(w, 0) + max(1, math.ceil((s[u] + thr) / -v))
                    changed = True
                    s = scores(base, W, c)
                    if s[u] <= -thr:
                        break
            bad = [u for u in s if u not in target and s[u] > -thr]
            if bad or max(c.values(), default=0) > cap:
                WHY.append(('bad', bad[:3]) if bad else ('cap', dict(c)))
                break
            if not changed:
                ok = True
                break
        if ok and predict(base, W, c) == list(target):
            return c
    return None


class Solver:
    def __init__(self, io):
        self.io = io
        self.est = Est()
        self.drivers = {}
        self.stage_q = {}

    def mark(self, name):
        self.stage_q[name] = self.io.queries

    def ask(self, counts):
        prompt = ' '.join(w for w, n in sorted(counts.items()) for _ in range(n))
        r = self.io.ask(prompt)
        y, floor = self.est.add(counts, r)
        return r, y, floor


    def recon(self):
        for js in ('{}', '{"fn":"x"}', '{"fn":"read_doc"}',
                   '{"fn":"read_doc","path":"a","z":1}',
                   '{"fn":"read_doc","fn":"read_doc","path":"a"}'):
            out = self.io.check(js)
            say('  CHECK', js, '->', [l.strip() for l in out][1])
        self.mark('recon')


    def discover(self):
        r0, y0, f0 = self.ask({})
        self.y0, self.f0 = y0, f0
        words = WORDS[:]
        random.Random(7).shuffle(words)
        groups = [words[i:i + 4] for i in range(0, len(words), 4)]
        hit = {}
        for g in groups:
            c = {w: 2 for w in g}
            _, y, f = self.ask(c)
            for w in g:
                self.est.prior[(w, w)] = 1.6
            for t, v in y.items():
                if t in NEED and self.rose(t, v):
                    if t not in hit or v > hit[t][1]:
                        hit[t] = (g, v)
        self.mark('groups')
        cand = {t: list(g) for t, (g, _) in hit.items()}
        missing = [t for t in NEED if t not in cand]
        if missing:
            say('  not lifted by any group:', missing)
        while any(len(s) > 1 for s in cand.values()):
            halves = {t: s[:len(s) // 2] for t, s in cand.items() if len(s) > 1}
            batches, cur = [], set()
            for t, h in halves.items():
                if len(cur | set(h)) > 5:
                    batches.append(cur); cur = set()
                cur |= set(h)
            batches.append(cur)
            for bset in batches:
                c = {w: 4 for w in bset}
                _, y, f = self.ask(c)
                for t, h in halves.items():
                    if set(h) <= bset:
                        up = t in y and self.rose(t, y[t])
                        cand[t] = h if up else [w for w in cand[t] if w not in h]
        for t, s in cand.items():
            self.drivers[t] = s[:1]
            self.est.prior[(s[0], t)] = 2.2
        self.mark('split')
        say('  drivers:', {t: s[0] for t, s in cand.items()})

    def rose(self, t, v):
        if t in self.y0:
            return v > self.y0[t] + 1.0
        return True


    def steer(self, target, label, max_iter=7):
        for t in target:
            if t in WORDS and t not in self.drivers:
                self.drivers[t] = [t]
                self.est.prior.setdefault((t, t), 1.6)
        for it in range(max_iter):
            toks = set(target) | {t for _, y, _ in self.est.obs for t in y}
            self.est.fit(toks, self.y0, self.f0)
            base, W = self.est.params(self.f0 or -3.0)
            c = None
            for m in (0.45, 0.6, 0.3, 0.8):
                c = plan(base, W, target, self.drivers, margin=m, seed=it)
                if c:
                    break
            if not c:
                say(f'  [{label}] planner found nothing (iter {it})', WHY[-3:])
                return None
            r, y, f = self.ask(c)
            if f is not None:

                for t in target:
                    if t not in y:
                        y[t] = f - 0.3
            got = self.string_tokens(r)
            say(f'  [{label}] iter {it}: {r["call"]}')
            if got == list(target):
                return r
            for u, v in y.items():
                if u not in target and u != CLOSER and v > -0.5:
                    for w in c:
                        self.est.prior.setdefault((w, u), 0.0)
        return None

    @staticmethod
    def string_tokens(r):
        out = []
        for step in r['trace'][STR_FIRST:]:
            if step[0][0] == CLOSER:
                break
            out.append(step[0][0])
        return out

    def run(self):
        t0 = time.time()
        self.recon()
        self.discover()
        r = self.steer(['change', 'log'], 'changelog')
        self.mark('changelog')
        text = '\n'.join(r['result'])
        hidden = re.search(r'executor-only tool (\S+)', text).group(1)
        vdoc = re.search(r'vault index is (\S+)', text).group(1)
        pfx = next(p for p in ('vault_', 'cold_', 'deep_', 'dark_') if hidden.startswith(p))
        verb = hidden[len(pfx):]
        docword = vdoc[:-1]
        say(f'  hidden tool={hidden} vault index={vdoc}')
        ra = self.steer([docword, 's"', ',"', 'f', '\\u006e"', ':"', pfx, verb], 'A')
        self.mark('A')
        txt = '\n'.join(ra['result'])
        frag_a = re.search(r'part one: (\S+)', txt).group(1)
        keyfile = re.search(r'above the vault: (\S+)', txt).group(1)
        kw = keyfile[:-3]
        rb = self.steer(['．．', '／', kw, '.md"', ',"', 'f', '\\u006e"', ':"',
                         pfx, verb], 'B')
        self.mark('B')
        frag_b = re.search(r'part two: (\S+)', '\n'.join(rb['result'])).group(1)
        flag = 'OVERPASS{' + frag_a + frag_b + '}'
        self.elapsed = time.time() - t0
        return flag


def main():
    global QUIET
    QUIET = '--quiet' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    host, port = (args + ['127.0.0.1', '1341'])[:2] if args else ('127.0.0.1', '1341')
    for attempt in range(1, 7):
        io = Remote(host, int(port))
        s = Solver(io)
        try:
            flag = s.run()
        except Exception as e:
            print(f'session {attempt}: gave up after {io.queries} queries ({type(e).__name__}); reconnecting')
            io.s.close()
            continue
        prev = 0
        for k, v in s.stage_q.items():
            say(f'  queries[{k}] = {v - prev}')
            prev = v
        print(f'session {attempt}: queries used {io.queries} / 50   time {s.elapsed:.1f}s')
        print('FLAG', flag)
        return flag
    sys.exit('no flag in 6 sessions')

if __name__ == '__main__':
    main()
