"""Lane STORED-XSS — rileva il reflected XSS PERSISTENTE (due passi).

A differenza del reflected (un solo giro: il payload torna nella STESSA
risposta che lo riceve), lo stored-XSS vive in due endpoint distinti: l'input
entra da un endpoint di SCRITTURA (es. `POST /commento`) e riemerge — magari in
un altro momento, verso un'altra vittima — da un endpoint di LETTURA (es.
`GET /commenti`). È una superficie di detection diversa dal reflected: la lane
`xss` puntata contro l'endpoint di lettura NON la vede, perché il payload non
sta in un suo parametro ma nello stato persistito dal server.

Metodo (stessa prova oggettiva del reflected, ma su DUE richieste):
  1. SCRITTURA — invio un canary unico con caratteri pericolosi (`<ar>`) al
     primo endpoint.
  2. LETTURA  — faccio una richiesta al secondo endpoint e guardo il corpo.
Tre esiti:
  - canary assente        → non persistito / non reso lì   → ok
  - canary ESCAPATO        → persistito ma `&lt;ar&gt;`     → ok (output encoding)
  - canary CRUDO (`<ar>`)  → persistito NON-escapato         → STORED XSS (ALTO)

Il token casuale nel canary garantisce che il match sia proprio ciò che abbiamo
appena scritto (non un residuo vecchio della bacheca).

Limite onesto: come il reflected, la prova è la presenza del canary CRUDO nel
corpo reso dall'endpoint di lettura (assume che quel corpo sia HTML, non un dato
JSON). Serve indicare i due endpoint (scrittura + lettura): è la natura stessa
del vettore stored, non un'assunzione della lane. ATTIVO: manda payload, SOLO
host in allowlist (via core.probe).
"""

import json
import secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl


def stored_xss(write_url, read_url, param="comment", write_method="POST",
               write_as="json", read_method="GET", other=None, session=None):
    """Scrive un canary pericoloso su `write_url` e verifica se riemerge
    NON-escapato leggendo `read_url`. Il PoC riproduce la richiesta di scrittura
    (l'iniezione); la lettura è una GET semplice descritta nell'evidenza.

    `session` (dict di header: Cookie / Bearer / custom) è instradata in ENTRAMBE
    le probe (scrittura + lettura) → raggiunge una bacheca DIETRO il login; il PoC
    la riporta MASCHERATA (`$TOKEN`/`$COOKIE`), il segreto non entra nel referto."""
    other = dict(other or {})
    token = "ar1es" + secrets.token_hex(3)
    canary = f"{token}<ar>"                      # token + tag finto coi caratteri chiave

    body_obj = dict(other)
    body_obj[param] = canary
    if write_as == "json":
        wu, wh, wb = write_url, {"Content-Type": "application/json"}, json.dumps(body_obj)
    elif write_as == "form":
        wu, wh, wb = write_url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(body_obj)
    else:  # query string
        sep = "&" if "?" in write_url else "?"
        wu, wh, wb = write_url + sep + urlencode(body_obj), {}, None

    w = probe(wu, write_method, wh, wb, session=session)
    if "error" in w:
        return finding(f"stored-xss:{param}", write_url, "ERRORE", "info",
                       "probe di SCRITTURA fallita", w["error"])

    r = probe(read_url, read_method, session=session)
    if "error" in r:
        return finding(f"stored-xss:{param}", read_url, "ERRORE", "info",
                       "probe di LETTURA fallita", r["error"])

    body = r.get("body_head", "")
    wrote = f"scrittura HTTP {w.get('status')}, lettura HTTP {r.get('status')}"
    if token not in body:
        return finding(f"stored-xss:{param}", read_url, "non persistito/non reso", "ok",
                       "il canary scritto NON riemerge dall'endpoint di lettura "
                       "(non stored, reso altrove, o input scartato)",
                       f"canary assente nella lettura ({wrote})")
    if canary in body:                           # i caratteri < > tornano CRUDI
        return finding(f"stored-xss:{param}", read_url, "VULNERABILE (stored)", "high",
                       "input PERSISTITO e reso NON-escapato in un secondo endpoint "
                       "→ stored XSS (colpisce chi legge, senza interazione)",
                       f"canary crudo nella lettura di {read_url}: {canary} "
                       f"(scritto su {write_url})",
                       as_curl(wu, write_method, wh, wb, session=session))
    return finding(f"stored-xss:{param}", read_url, "persistito ma escapato", "ok",
                   "il canary è persistito ma i caratteri pericolosi sono codificati "
                   "(output encoding ok in lettura)",
                   f"token presente nella lettura, '<ar>' codificato (es. &lt;ar&gt;) ({wrote})")


def run(write_url, read_url, param="comment", write_as="json", other=None, session=None):
    return [stored_xss(write_url, read_url, param=param, write_as=write_as,
                       other=other, session=session)]
