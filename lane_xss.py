"""Lane XSS — rileva reflected XSS LATO SERVER.

Metodo: inietto un canary unico con caratteri pericolosi (`<ar>`), e guardo se
torna nella risposta HTTP. Tre esiti oggettivi:
  - canary assente        → il parametro non si riflette (o non lato server)
  - canary ESCAPATO        → riflesso ma `&lt;ar&gt;` = sicuro (output encoding ok)
  - canary CRUDO (`<ar>`)  → riflesso non-escapato = reflected XSS

Limite onesto: rileva il reflected SERVER-SIDE (nel corpo della risposta). Il
DOM/client-side XSS (SPA che riflette nel browser) serve un browser headless →
lane futura. ATTIVO: manda payload, SOLO host in allowlist (via core.probe).
"""

import json
import secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl


def xss_reflected(url, param="q", method="GET", send_as="query", other=None, session=None):
    other = dict(other or {})
    token = "ar1es" + secrets.token_hex(3)
    canary = f"{token}<ar>"                      # token + tag finto coi caratteri chiave
    other[param] = canary

    if send_as == "json":
        u, h, b = url, {"Content-Type": "application/json"}, json.dumps(other)
    elif send_as == "form":
        u, h, b = url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(other)
    else:  # query string
        sep = "&" if "?" in url else "?"
        u, h, b = url + sep + urlencode(other), {}, None
    # `session` (Cookie/Bearer/header custom) raggiunge la superficie LOGGATA: un
    # XSS dietro l'autenticazione è invisibile senza la sessione (login wall).
    resp = probe(u, method, h, b, session=session)

    if "error" in resp:
        return finding(f"xss:{param}", url, "ERRORE", "info", "probe fallita", resp["error"])

    body = resp.get("body_head", "")
    if token not in body:
        return finding(f"xss:{param}", url, "non riflessa", "ok",
                       "il parametro non si riflette nella risposta (o è client-side)",
                       f"canary non trovato (HTTP {resp.get('status')})")
    if canary in body:                           # i caratteri < > tornano CRUDI
        return finding(f"xss:{param}", url, "VULNERABILE (reflected)", "high",
                       "input riflesso NON-escapato → XSS reflected lato server",
                       f"canary crudo nella risposta: {canary}",
                       as_curl(u, method, h, b, session=session))
    return finding(f"xss:{param}", url, "riflessa ma escapata", "ok",
                   "l'input si riflette ma i caratteri pericolosi sono codificati (output encoding ok)",
                   f"token presente, '<ar>' codificato (es. &lt;ar&gt;)")


def run(url, param="q", send_as="query", other=None, session=None):
    return [xss_reflected(url, param=param, send_as=send_as, other=other, session=session)]
