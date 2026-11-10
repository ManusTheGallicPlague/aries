"""Lane REDIRECT — rileva l'OPEN REDIRECT (modulo transport/logica, offensivo).

Metodo: il parametro di redirect (default `to`) controlla dove l'app manda
l'utente? Inietto un **canary esterno** (`aries-oredir-<token>.example.com`) e
guardo l'header `Location` della risposta. Il canary NON viene mai contattato:
`core.probe` non segue i redirect (vediamo il 3xx, non lo eseguiamo).

Tre esiti oggettivi:
  - Location finisce sul canary (host esterno)  → OPEN REDIRECT (vulnerabile)
  - redirect presente ma resta interno/validato → safe
  - nessun redirect verso l'esterno             → il param non porta fuori

Provo una batteria di payload canonici (assoluto, protocol-relative, schema
malformato). Con `--allowed <url>` aggiungo le varianti **bypass-allowlist**
(canary + un URL consentito come query/fragment): è il trucco contro i
validatori a "substring" (es. il /redirect di Juice Shop).

ATTIVO: manda richieste → SOLO host in allowlist (via core.probe). Il canary è
in valore, non è il bersaglio: resta fuori dallo scope e non viene aperto.
"""

import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core import finding, probe, as_curl

_REDIRECT_STATUS = {301, 302, 303, 307, 308}


def _with_param(url, param, value):
    """Rimpiazza (o aggiunge) un parametro nella query, preservando il resto."""
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    q[param] = [value]
    return urlunparse(u._replace(query=urlencode(q, doseq=True)))


def _payloads(canary, allowed):
    base = [
        f"https://{canary}/",      # assoluto esplicito
        f"//{canary}/",            # protocol-relative (spesso dimenticato dai filtri)
        f"https:/{canary}/",       # schema malformato: alcuni normalizzatori lo "aggiustano"
        f"https://{canary}",       # senza slash finale
    ]
    if allowed:                    # bypass dei validatori a substring: host=canary, l'allowed sta altrove
        base += [
            f"https://{canary}/?x={allowed}",
            f"https://{canary}/{allowed}",
            f"https://{canary}#{allowed}",
        ]
    return base


def _lands_external_on(loc, canary):
    """True se Location punta DAVVERO al canary come host esterno."""
    if not loc:
        return False
    lp = urlparse(loc)
    external = lp.scheme in ("http", "https") or loc.lstrip().startswith("//")
    return external and (lp.hostname or "").lower() == canary.lower()


def redirect(url, param="to", allowed=None, method="GET", session=None):
    """`session` (dict di header: Cookie / Bearer / custom) è instradata in ogni
    probe → raggiunge un endpoint di redirect DIETRO il login; il PoC la riporta
    MASCHERATA (`$TOKEN`/`$COOKIE`), il segreto non entra nel referto."""
    canary = f"aries-oredir-{secrets.token_hex(3)}.example.com"
    saw_redirect = False                         # l'endpoint fa 3xx almeno una volta?
    for pl in _payloads(canary, allowed):
        resp = probe(_with_param(url, param, pl), method, session=session)
        if "error" in resp:
            return finding(f"redirect:{param}", url, "ERRORE", "info", "probe fallita", resp["error"])
        loc = resp.get("headers", {}).get("location", "")
        if resp.get("status") in _REDIRECT_STATUS and loc:
            saw_redirect = True
            if _lands_external_on(loc, canary):
                return finding(
                    f"redirect:{param}", url, "VULNERABILE (open redirect)", "high",
                    "il parametro porta l'utente verso un host ESTERNO arbitrario → phishing/furto token",
                    f"payload '{pl}' → HTTP {resp['status']} Location: {loc}",
                    as_curl(_with_param(url, param, pl), method, session=session))
    if saw_redirect:
        return finding(f"redirect:{param}", url, "redirect validato", "ok",
                       "l'endpoint reindirizza ma NON verso l'esterno (origine validata)",
                       f"nessun payload esterno accettato (param {param})")
    return finding(f"redirect:{param}", url, "nessun open redirect", "ok",
                   "il parametro non genera un redirect verso l'esterno",
                   f"nessun 3xx verso il canary (param {param})")


def run(url, param="to", allowed=None, session=None):
    return [redirect(url, param=param, allowed=allowed, session=session)]
