"""Lane DISCOVERY (fuzz) — dà input malformati a un parser e cerca crash/hang.

Un crash è OGGETTIVO: o solleva un'eccezione non prevista, o si pianta. È così
che si trovano 0-day veri, ed è meccanico.

Bersaglio: una directory che contiene un modulo `formula.py` che espone
`compute(text, ctx)` e un'eccezione `FormulaError`. Regola: il parser dichiara
UN solo errore "buono", `FormulaError`; tutto il resto (RecursionError,
ZeroDivisionError, TIMEOUT…) è un BUG.

Il percorso del bersaglio e il contesto d'esempio NON stanno nel repo (così
resta generico): vengono da `config_local.py` (`FUZZ_TARGET` / `FUZZ_CONTEXT`),
oppure dalla variabile d'ambiente `ARIES_FUZZ_TARGET`. Senza un bersaglio
configurato la lane lo dichiara e non fa nulla.
"""

import importlib
import os
import random
import signal
import string
import sys

from core import finding

try:
    import config_local as _local
except ImportError:
    _local = None

# Bersaglio del fuzzer: config_local.FUZZ_TARGET, poi env ARIES_FUZZ_TARGET.
FUZZ_TARGET = getattr(_local, "FUZZ_TARGET", None) or os.environ.get("ARIES_FUZZ_TARGET")
# Contesto passato al parser: config_local.FUZZ_CONTEXT o un default neutro.
SAMPLE_CTX = getattr(_local, "FUZZ_CONTEXT", None) or {
    "a": 1.0, "b": 2.5, "x": 10.0, "y": 0.0, "z": 100.0,
}


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


signal.signal(signal.SIGALRM, _on_alarm)


def _load_formula():
    if not FUZZ_TARGET:
        raise RuntimeError(
            "nessun bersaglio di fuzz configurato: imposta FUZZ_TARGET in "
            "config_local.py (o la variabile d'ambiente ARIES_FUZZ_TARGET) a una "
            "directory che contiene un modulo formula.py")
    if FUZZ_TARGET not in sys.path:
        sys.path.insert(0, FUZZ_TARGET)
    return importlib.import_module("formula")


def _run_one(mod, text, timeout=2.0):
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        mod.compute(text, SAMPLE_CTX)
        return ("ok", None)
    except mod.FormulaError:
        return ("FormulaError", None)                 # previsto, va bene
    except _Timeout:
        return ("TIMEOUT", f"stallo > {timeout}s (DoS)")
    except RecursionError:
        return ("RecursionError", "ricorsione non gestita → crash del worker (DoS)")
    except Exception as e:                             # noqa: BLE001
        return (type(e).__name__, str(e)[:120])
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def _is_bug(esito):
    return esito not in ("ok", "FormulaError")


def _directed():
    yield "parentesi_annidate", "(" * 300 + "1" + ")" * 300
    yield "unario_profondo", "-" * 2000 + "1"
    yield "not_profondo", "not " * 2000 + "1"
    yield "catena_somma", "1" + "+1" * 20000
    yield "if_annidati", "if(1," * 300 + "1" + ",0)" * 300
    yield "divisione_zero", "1/0"
    yield "numero_enorme", "9" * 400


_TOKENS = ["(", ")", "+", "-", "*", "/", "<", ">", "==", "!=", ",", "and", "or",
           "not", "min", "max", "if", "coalesce", "nonzero", "1", "3.14",
           "a", "b", "x"]
_CHARS = string.ascii_letters + string.digits + "+-*/()<>=!,. _"


def _random_case(rnd):
    if rnd.random() < 0.5:
        return " ".join(rnd.choice(_TOKENS) for _ in range(rnd.randint(1, 40)))
    return "".join(rnd.choice(_CHARS) for _ in range(rnd.randint(1, 80)))


def _min_parens(mod):
    def crashes(n):
        return _is_bug(_run_one(mod, "(" * n + "1" + ")" * n)[0])
    if not crashes(2000):
        return None
    lo, hi = 1, 2000
    while lo < hi:
        mid = (lo + hi) // 2
        hi, lo = (mid, lo) if crashes(mid) else (hi, mid + 1)
    return lo


def run(target=None, iters=20000):
    """Fuzza `formula.compute`. `target` è ignorato per ora (un solo parser);
    il parametro resta per quando generalizzeremo ad altri bersagli."""
    try:
        mod = _load_formula()
    except Exception as e:                             # noqa: BLE001
        return [finding("fuzz:load", target or "formula.py", "ERRORE", "info",
                        f"non riesco a caricare il parser (bersaglio: {FUZZ_TARGET or 'non configurato'})", str(e))]

    out, seen = [], set()
    for label, text in _directed():
        esito, det = _run_one(mod, text)
        if _is_bug(esito):
            out.append(finding(f"fuzz:{label}", "formula.compute", esito, "med",
                               det or "", f"input lungo {len(text)} char"))
    rnd = random.Random(1337)
    for _ in range(iters):
        esito, det = _run_one(mod, _random_case(rnd))
        if _is_bug(esito) and esito not in seen:
            seen.add(esito)
            out.append(finding("fuzz:random", "formula.compute", esito, "med", det or "", "input random"))

    thr = _min_parens(mod)
    if thr is not None:
        out.append(finding("fuzz:soglia-ricorsione", "formula.compute",
                           f"crash a {thr} livelli", "info",
                           "profondità minima di annidamento che fa RecursionError",
                           f"({thr} parentesi annidate → DoS del recompute)"))
    if not out:
        out.append(finding("fuzz", "formula.compute", "nessun crash", "ok",
                           "il parser regge a tutti gli input provati", ""))
    return out
