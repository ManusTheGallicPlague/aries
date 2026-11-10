"""Lane SSTI — rileva Server-Side Template Injection (valutazione lato server).

Metodo: inietto un **marker unico** seguito da un'espressione aritmetica dentro
i vari delimitatori di template (`{{…}}`, `${…}`, `#{…}`, `<%= … %>`). Poi guardo
cosa torna nella risposta — tre esiti oggettivi:
  - marker + PRODOTTO calcolato (`marker783221`) → il motore ha VALUTATO l'espressione
    → SSTI confermata (iniezione nel contesto del template; l'escalation a RCE
    dipende dal motore/sandbox).
  - marker + payload LETTERALE (`marker{{887*883}}`) → riflesso ma NON valutato
    (è semplice reflection, non SSTI — la trappola classica dei falsi positivi).
  - marker assente → il parametro non si riflette.

I fattori sono distinti e il prodotto (887*883 = 783221) non compare nel letterale,
così `marker + prodotto` è inconfondibile. Il marker è casuale → nessuna collisione.

ATTIVO: manda payload, SOLO host in allowlist (il confine vive in core.probe).
"""

import json
import secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl

# Fattori distinti: il prodotto non è un sottostringa del letterale "887*883".
_A, _B = 887, 883
_PROD = _A * _B                                  # 783221

# Batteria di sintassi: motori diversi valutano delimitatori diversi. Ognuna è
# (template_dell'espressione, nome_del_motore_tipico).
_SYNTAXES = [
    ("{{%d*%d}}" % (_A, _B), "Jinja2/Twig/Nunjucks ({{…}})"),
    ("${%d*%d}" % (_A, _B), "Freemarker/JSP-EL/Spring (${…})"),
    ("#{%d*%d}" % (_A, _B), "Freemarker/Ruby-interp (#{…})"),
    ("<%%= %d*%d %%>" % (_A, _B), "ERB/EJS (<%= … %>)"),
]


def _send(url, param, payload, method, send_as, other, session=None):
    """Costruisce e manda la richiesta con `payload` in `param`. Ritorna
    (resp, u, h, b) così il PoC curl nasce dalla STESSA tripla inviata. `session`
    (Cookie/Bearer/header) raggiunge la superficie LOGGATA: una SSTI dietro
    l'autenticazione è invisibile senza la sessione (login wall)."""
    o = dict(other or {})
    o[param] = payload
    if send_as == "json":
        u, h, b = url, {"Content-Type": "application/json"}, json.dumps(o)
    elif send_as == "form":
        u, h, b = url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(o)
    else:  # query string
        sep = "&" if "?" in url else "?"
        u, h, b = url + sep + urlencode(o), {}, None
    return probe(u, method, h, b, session=session), u, h, b


def ssti_inject(url, param="q", method="GET", send_as="query", other=None, session=None):
    token = "ar1es" + secrets.token_hex(3)
    evaluated = token + str(_PROD)               # marker seguito dal prodotto CALCOLATO
    reflected_literal = False                    # il payload torna crudo (reflection, non SSTI)
    last_err = None

    for expr, engine in _SYNTAXES:
        payload = token + expr                   # es. ar1es9f2c{{887*883}}
        resp, u, h, b = _send(url, param, payload, method, send_as, other, session=session)
        if "error" in resp:
            last_err = resp["error"]
            continue
        body = resp.get("body_head", "")
        if evaluated in body:                    # il motore ha sostituito l'espressione col risultato
            return finding(f"ssti:{param}", url, "VULNERABILE (SSTI)", "high",
                           f"il template valuta l'espressione iniettata ({engine}) → "
                           f"SSTI confermata (escalation a RCE dipende dal motore/sandbox)",
                           f"iniettato '{payload}', la risposta contiene '{evaluated}' "
                           f"({_A}*{_B}={_PROD} calcolato lato server)",
                           as_curl(u, method, h, b, session=session))
        if payload in body or token in body:
            reflected_literal = True

    if last_err and not reflected_literal:
        return finding(f"ssti:{param}", url, "ERRORE", "info", "probe fallita", last_err)
    if reflected_literal:
        return finding(f"ssti:{param}", url, "riflessa ma non valutata", "ok",
                       "l'input si riflette ma le espressioni template NON vengono "
                       "valutate (reflection, non SSTI)",
                       f"payload riflesso letterale (nessun '{evaluated}' nella risposta)")
    return finding(f"ssti:{param}", url, "non riflessa", "ok",
                   "il parametro non si riflette nella risposta (o non lato server)",
                   f"marker '{token}' non trovato in nessuna delle {len(_SYNTAXES)} sintassi")


def run(url, param="q", send_as="query", other=None, session=None):
    return [ssti_inject(url, param=param, send_as=send_as, other=other, session=session)]
