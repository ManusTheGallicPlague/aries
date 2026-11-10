"""Lane AUTH — test runtime della resistenza al brute-force sul login.

Manda N tentativi di login FALLITI (username FINTO, così non tocca account veri)
e guarda se il server inizia a limitare. Riconosce il throttling/lockout da TRE
segnali, dal più esplicito al più sottile:
  1. status **429** (Too Many Requests) o **423** (Locked) → throttle esplicito;
  2. un header **`Retry-After`** (RFC 7231) su qualunque risposta → segnale di
     "rallenta" status-agnostico (una difesa che non cambia lo status);
  3. una **transizione di status** TARDIVA e PERSISTENTE verso uno status
     bloccante (es. 401→403 dopo i primi tentativi, e ci resta): è il modo in cui
     molte app reali fanno lockout IP/account o step-up SENZA il 429 canonico.
Nessuno dei tre → tutti falliti allo stesso modo (es. 401) senza throttling →
VULNERABILE (brute-force / credential-stuffing possibili).

I segnali 2 e 3 esistono perché un login che si difende con un metodo diverso dal
429 sarebbe altrimenti un FALSO POSITIVO: è la robustezza misurata dal banco
avversariale (trappola `/trap-auth-lockout`, un login sano ma ingannevole).

ATTIVO: manda richieste → SOLO host in allowlist. Username finto e tentativi
limitati (default 8): non blocca utenti reali.

Limite onesto: con username finto testa soprattutto il throttling per-IP; un
lockout SOLO per-username su utenti esistenti non verrebbe esercitato (e non lo
facciamo apposta, per non bloccare nessuno).
"""

import json
from urllib.parse import urlencode

from core import finding, probe, as_curl

_FAKE_USER = "aries_bruteforce_probe"

# Status "bloccanti": comparsi come TRANSIZIONE tardiva (il server ci passa dopo i
# primi tentativi e ci resta) segnalano un lockout/step-up anche senza il 429
# canonico — 403 (IP/account bloccato), 429/423 (throttle/lock espliciti), 503
# (circuit-breaker). Usati da `_lockout_transition`.
_BLOCK = (403, 429, 423, 503)


def _lockout_transition(statuses):
    """Riconosce un LOCKOUT per TRANSIZIONE di status (throttling che NON passa
    dal 429 canonico): il server risponde con uno status di fallimento COSTANTE ai
    primi tentativi, poi PASSA a uno status bloccante (403/423/429/503) DIVERSO e
    ci RESTA fino alla fine. Puro, nessuna rete: decide solo dalla sequenza.

    CONSERVATIVO per non silenziare i veri vulnerabili (un falso negativo qui è
    peggio di un falso positivo): pretende una transizione
      - TARDIVA     → il PRIMO tentativo NON è già lo status bloccante, e
      - PERSISTENTE → la CODA finale è tutta lo stesso status bloccante, lunga ≥2.
    Un login davvero senza throttling (stesso status ogni volta, es. 401×N) non ha
    transizione → resta VULNERABILE; un 403-sempre (fallimento costante, non una
    reazione ai tentativi) non è transizione → resta VULNERABILE; un singolo
    status sporco a metà sequenza non basta (serve la coda stabile)."""
    if len(statuses) < 3:
        return False
    first, last = statuses[0], statuses[-1]
    if last == first or last not in _BLOCK:
        return False
    tail = 0
    for s in reversed(statuses):
        if s == last:
            tail += 1
        else:
            break
    return 2 <= tail < len(statuses)


def auth_bruteforce(url, field="username", method="POST", send_as="json",
                    attempts=8, other=None):
    other = dict(other or {})
    other.setdefault("password", "wrong-pw-xyz")
    other[field] = _FAKE_USER

    if send_as == "json":
        u, h, b = url, {"Content-Type": "application/json"}, json.dumps(other)
    elif send_as == "form":
        u, h, b = url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(other)
    else:
        sep = "&" if "?" in url else "?"
        u, h, b = url + sep + urlencode(other), {}, None

    statuses = []
    for _ in range(attempts):
        r = probe(u, method, h, b)
        if "error" in r:
            return finding("auth:bruteforce", url, "ERRORE", "info", "probe fallita", r["error"])
        st = r["status"]
        statuses.append(st)
        # Segnali ESPLICITI di throttling: 429/423, o un `Retry-After` (RFC 7231,
        # status-agnostico → una difesa che non cambia lo status).
        retry_after = r.get("headers", {}).get("retry-after")
        if st in (429, 423) or retry_after:
            extra = f", Retry-After: {retry_after}" if retry_after else ""
            return finding("auth:bruteforce", url, "rate-limit presente", "ok",
                           "il login limita i tentativi (429/lockout/Retry-After) → brute-force ostacolato",
                           f"sequenza status: {statuses}{extra}")

    # Nessun segnale esplicito: cerca un LOCKOUT per TRANSIZIONE di status (il
    # server inizia a bloccare dopo i primi tentativi, es. 401→403) — un throttle
    # che non usa il 429 canonico resterebbe altrimenti un FALSO POSITIVO.
    if _lockout_transition(statuses):
        return finding("auth:bruteforce", url, "lockout presente (transizione di status)", "ok",
                       "dopo i primi tentativi il server passa a uno status bloccante e ci resta "
                       "(lockout IP/account o step-up) → brute-force ostacolato",
                       f"sequenza status: {statuses}")

    repro = (f"for i in $(seq 1 {attempts}); do " + as_curl(u, method, h, b, status_only=True)
             + "; done; echo   # tutti 401, nessun 429/lockout = vulnerabile")
    return finding("auth:bruteforce", url, "VULNERABILE (no rate-limit)", "high",
                   f"{attempts} login falliti senza throttling né lockout → brute-force / credential-stuffing possibili",
                   f"sequenza status: {statuses}", repro)


def run(url, field="username", send_as="json", attempts=8, other=None):
    return [auth_bruteforce(url, field=field, send_as=send_as, attempts=attempts, other=other)]
