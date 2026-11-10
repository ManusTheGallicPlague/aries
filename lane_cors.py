"""Lane CORS — rileva la MISCONFIGURAZIONE CORS (modulo transport/logica, offensiva).

Metodo: il server si fida di CHI chiede? Mando un header `Origin` **arbitrario**
(attaccante) e guardo come risponde la coppia che decide la condivisione
cross-origin:
  - `Access-Control-Allow-Origin`      (ACAO) — quale origine può leggere la risposta
  - `Access-Control-Allow-Credentials` (ACAC) — se cookie/Authorization valgono cross-origin

Il caso grave è oggettivo: l'ACAO **riflette** l'origine arbitraria che ho
mandato *e* l'ACAC è `true`. Allora un sito malevolo, con la sessione della
vittima, legge le risposte autenticate cross-origin (furto dati/sessione).

Due FASI per ogni origine (la seconda è il vero controllo CORS):
  1. **richiesta semplice** (GET con `Origin`) — il caso base.
  2. **preflight OPTIONS** con metodo/header non-simple
     (`Access-Control-Request-Method`/`-Headers`) — molti middleware CORS
     riflettono l'origine **solo** nella risposta al preflight, o solo quando la
     richiesta non è simple (PUT/DELETE o header custom come `Authorization`).
     Senza questa fase quei server passano per sicuri: falso negativo.

Batteria di origini attaccante (nessuna è un host reale contattato — stanno solo
nell'header, il bersaglio resta in ALLOWLIST via core.probe):
  - un'origine esterna arbitraria              → riflessione cieca (il bug più comune)
  - `null`                                     → iframe sandbox/`data:` producono Origin: null
  - un sottodominio dell'host sotto un dominio attaccante → validatori ingenui `startswith`

Classificazione onesta (si tiene il peggio tra origini e fasi):
  - origine arbitraria riflessa **+ credenziali**        → CRIT  (lettura autenticata cross-origin)
  - origine arbitraria riflessa, **senza** credenziali   → MEDIO (solo risposte non autenticate)
  - `ACAO: *` **+** credenziali                          → BASSO (i browser lo rifiutano: inerte)
  - `ACAO: *` senza credenziali                          → INFO  (API pubblica: atteso)
  - nessuna origine arbitraria riflessa                  → ok    (allowlist o CORS assente)

ATTIVO: manda richieste → SOLO host in allowlist (via core.probe).
"""

import secrets
from urllib.parse import urlparse

from core import finding, probe, as_curl, SEV_ORDER


def _attacker_origins(host):
    """Origini che un attaccante controllerebbe: arbitraria, null, suffix-bypass."""
    rnd = secrets.token_hex(3)
    evil = f"https://aries-cors-{rnd}.example.com"
    return [
        ("arbitraria", evil),                                  # origine esterna qualsiasi
        ("null", "null"),                                      # Origin: null (sandbox/data:)
        ("suffix-bypass", f"https://{host}.aries-cors-{rnd}.example.com"),  # validatore startswith(host)
    ]


# Richiesta preflight: metodo + header NON-simple → forza il vero controllo CORS
# lato server (è la condizione che molti middleware gestiscono separatamente).
_PF_METHOD = "PUT"
_PF_HEADERS = "authorization, x-aries"


def _classify(url, label, origin, fase, acao, acac, repro, extra=""):
    """Dà il finding per UNA risposta (`fase` = 'GET semplice' | 'preflight OPTIONS').
    Ritorna None quando non c'è nulla di rilevante (nessuna riflessione, nessun '*')."""
    reflected = bool(acao) and acao == origin   # ACAO deve combaciare ESATTO con l'Origin
    suff = f" · {extra}" if extra else ""
    if reflected and acac:
        return finding(
            "cors", url, "VULNERABILE (origine arbitraria riflessa + credenziali)", "crit",
            "il server riflette un Origin ARBITRARIO in ACAO e abilita le credenziali → "
            "un sito malevolo legge le risposte autenticate cross-origin (furto dati/sessione)",
            f"[{fase}] Origin '{origin}' ({label}) → ACAO '{acao}', ACAC true{suff}",
            repro)
    if reflected:
        return finding(
            "cors", url, "VULNERABILE (origine arbitraria riflessa, senza credenziali)", "med",
            "il server riflette un Origin arbitrario ma NON abilita le credenziali → "
            "lettura cross-origin delle sole risposte non autenticate (impatto minore)",
            f"[{fase}] Origin '{origin}' ({label}) → ACAO '{acao}', ACAC assente{suff}",
            repro)
    if acao == "*" and acac:
        return finding(
            "cors", url, "CORS wildcard + credenziali (inerte sui browser)", "low",
            "ACAO '*' con ACAC true: i browser RIFIUTANO questa combinazione con fetch "
            "credenziato → non sfruttabile da browser, ma configurazione incoerente da correggere",
            f"[{fase}] Origin '{origin}' ({label}) → ACAO '*', ACAC true{suff}", repro)
    if acao == "*":
        return finding(
            "cors", url, "CORS wildcard pubblico", "info",
            "ACAO '*' senza credenziali: atteso per API pubbliche → "
            "verifica che i dati esposti siano davvero pubblici",
            f"[{fase}] Origin '{origin}' ({label}) → ACAO '*'{suff}", repro)
    return None


def cors(url, method="GET", session=None):
    """Un referto CORS: tiene il finding più grave tra le origini e le DUE fasi
    (GET semplice + preflight OPTIONS). Il preflight becca i server che riflettono
    l'origine solo nella risposta al preflight o solo per richieste non-simple.
    `session` (Cookie/Bearer/header) raggiunge la superficie LOGGATA: una
    misconfigurazione CORS su un'API dietro l'autenticazione resta invisibile
    senza la sessione (login wall). L'header `Origin` arbitrario della lane resta
    esplicito → vince sempre sul collide con la sessione (confine ALLOWLIST
    invariato: `Origin` non è un host contattato, sta solo nell'header)."""
    host = (urlparse(url).hostname or "").lower()
    origins = _attacker_origins(host)
    best = None                                  # il finding peggiore visto finora

    def _keep(f):
        nonlocal best
        if f is not None and (best is None or SEV_ORDER[f["severity"]] < SEV_ORDER[best["severity"]]):
            best = f

    for label, origin in origins:
        # --- Fase 1: richiesta semplice (GET con Origin) ---
        resp = probe(url, method, headers={"Origin": origin}, session=session)
        if "error" in resp:
            return finding("cors", url, "ERRORE", "info", "probe fallita", resp["error"])
        h = resp.get("headers", {})
        acao = (h.get("access-control-allow-origin") or "").strip()
        acac = (h.get("access-control-allow-credentials") or "").strip().lower() == "true"
        repro = as_curl(url, method, headers={"Origin": origin}, session=session)
        f1 = _classify(url, label, origin, "GET semplice", acao, acac, repro)
        if f1 is not None and f1["severity"] == "crit":
            return f1                            # il peggio possibile: ritorno subito
        _keep(f1)

        # --- Fase 2: preflight OPTIONS con metodo/header non-simple ---
        pf_headers = {"Origin": origin,
                      "Access-Control-Request-Method": _PF_METHOD,
                      "Access-Control-Request-Headers": _PF_HEADERS}
        presp = probe(url, "OPTIONS", headers=pf_headers, session=session)
        if "error" in presp:
            continue                             # preflight fallito: non è un finding
        ph = presp.get("headers", {})
        pacao = (ph.get("access-control-allow-origin") or "").strip()
        pacac = (ph.get("access-control-allow-credentials") or "").strip().lower() == "true"
        acam = (ph.get("access-control-allow-methods") or "").strip()
        extra = f"ACAM '{acam}'" if acam else ""  # metodi non-simple ammessi cross-origin
        prepro = as_curl(url, "OPTIONS", headers=pf_headers, session=session)
        f2 = _classify(url, label, origin, "preflight OPTIONS", pacao, pacac, prepro, extra)
        if f2 is not None and f2["severity"] == "crit":
            return f2
        _keep(f2)

    if best is not None:
        return best
    return finding(
        "cors", url, "nessuna debolezza CORS", "ok",
        "nessun Origin arbitrario è stato riflesso (né in GET semplice né in preflight "
        "OPTIONS) e le credenziali non sono esposte cross-origin (allowlist attiva o CORS assente)",
        f"origini attacker testate: {len(origins)} × 2 fasi (semplice + preflight), nessuna riflessa in ACAO")


def run(url, session=None):
    return [cors(url, session=session)]
