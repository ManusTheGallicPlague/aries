"""Lane CSRF — enforcement del token anti-CSRF su un endpoint che cambia stato.

Domanda: una richiesta che CAMBIA STATO viene eseguita in base al SOLO cookie di
sessione (autorità ambientale che il browser allega da solo, anche su richieste
cross-site), o il server pretende un token anti-CSRF imprevedibile e lo VALIDA?

Prova differenziale OGGETTIVA (come il boolean-based SQLi / NoSQLi): tre
richieste alla stessa operazione di scrittura, una variabile cambiata per volta.

  - A  LEGITTIMA      cookie di sessione + token CSRF corretto  → esito di riferimento
  - C  TOKEN FORGIATO cookie di sessione + token CSRF SBAGLIATO → se l'esito è
       IDENTICO ad A, il token non è validato: il solo cookie decide → forgeable
  - D  SENZA COOKIE   token corretto ma NESSUN cookie di sessione → guardia: deve
       cambiare esito (l'endpoint è davvero autenticato via cookie, non aperto/morto)

CSRF dimostrata  ⟺  sig(C) == sig(A)  (il token errato è accettato come il giusto)
                 E  sig(D) != sig(A)  (il cookie invece conta: c'è autorità ambientale).

La guardia D chiude il falso positivo dell'endpoint che risponde UGUALE a tutto
(aperto/morto): lì anche togliere il cookie non cambierebbe nulla (D == A) e la
lane TACE — non esiste una sessione la cui autorità venga abusata cross-site.

Il verdetto nasce dal confronto delle risposte reali (status + lunghezza), non da
un parere. Limite onesto: prova la MANCATA validazione del token su un endpoint
cookie-autenticato (il cuore del CSRF); non modella la protezione via attributo
SameSite sui cookie (passiva, la copre `check`) né i preflight. ATTIVO: manda
richieste che CAMBIANO STATO, SOLO host in ALLOWLIST (via core.probe).
"""

import json as _json
import secrets as _secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl


def _sig(resp):
    """Firma confrontabile della risposta: (status, lunghezza_corpo)."""
    if "error" in resp:
        return (None, 0)
    return (resp["status"], len(resp.get("body_head", "")))


def _build(token_field, token_value, send_as, extra):
    """Corpo + Content-Type della richiesta, dal token CSRF (+ eventuali campi
    extra, costanti tra le tre richieste così l'unica variabile resta il token/cookie)."""
    fields = dict(extra or {})
    fields[token_field] = token_value
    if send_as == "json":
        return _json.dumps(fields), "application/json"
    return urlencode(fields), "application/x-www-form-urlencoded"


def csrf_probe(url, cookie, token, token_field="csrf_token", send_as="form", extra=None):
    """Testa l'enforcement del token anti-CSRF su un endpoint di scrittura.
    `cookie`: valore dell'header Cookie (la sessione, autorità ambientale).
    `token`: un token anti-CSRF VALIDO (quello della pagina legittima).
    Ritorna un Finding."""
    body_ok, ctype = _build(token_field, token, send_as, extra)
    forged = "aries_forged_" + _secrets.token_hex(4)          # token attaccante, mai quello buono
    body_bad, _ = _build(token_field, forged, send_as, extra)

    # A — legittima: cookie + token corretto
    rA = probe(url, "POST", {"Content-Type": ctype, "Cookie": cookie}, body_ok)
    # C — token forgiato: cookie + token SBAGLIATO (è la richiesta cross-site forgiabile)
    rC = probe(url, "POST", {"Content-Type": ctype, "Cookie": cookie}, body_bad)
    # D — senza cookie: token corretto ma NESSUNA sessione (guardia anti falso positivo)
    rD = probe(url, "POST", {"Content-Type": ctype}, body_ok)

    sA, sC, sD = _sig(rA), _sig(rC), _sig(rD)
    if sA[0] is None or sC[0] is None or sD[0] is None:
        err = rA.get("error") or rC.get("error") or rD.get("error")
        return finding("csrf", url, "ERRORE", "info", "probe fallita", str(err))

    # PoC: la richiesta C (cookie + token errato) col Cookie mascherato ($COOKIE).
    # Il browser della vittima allega il suo cookie da solo → questa è la forgiatura.
    poc = as_curl(url, "POST", {"Content-Type": ctype, "Cookie": "$COOKIE"}, body_bad)

    if sC == sA and sD != sA:
        return finding(
            "csrf", url, "VULNERABILE (token CSRF non validato)", "high",
            "token anti-CSRF non validato: una richiesta con token errato è accettata "
            "come la legittima e il solo cookie di sessione decide → forgeable cross-site "
            "(il browser allega il cookie da solo)",
            f"A legittima(HTTP {sA[0]},{sA[1]}b) · C token-errato(HTTP {sC[0]},{sC[1]}b) = A "
            f"· D senza-cookie(HTTP {sD[0]},{sD[1]}b) ≠ A (il cookie conta: autenticato)",
            poc)
    if sC != sA:
        return finding(
            "csrf", url, "non rilevata (token validato)", "ok",
            "un token CSRF errato cambia l'esito → il server valida il token anti-CSRF",
            f"A legittima(HTTP {sA[0]},{sA[1]}b) · C token-errato(HTTP {sC[0]},{sC[1]}b) ≠ A")
    return finding(
        "csrf", url, "non rilevata (sessione non determinante)", "ok",
        "togliere il cookie non cambia l'esito → l'endpoint non è autenticato via cookie "
        "(aperto/morto): nessuna autorità ambientale da abusare, CSRF non dimostrabile qui",
        f"A(HTTP {sA[0]},{sA[1]}b) · C token-errato(HTTP {sC[0]},{sC[1]}b) = A "
        f"· D senza-cookie(HTTP {sD[0]},{sD[1]}b) = A")


def run(url, cookie="", token="", token_field="csrf_token", send_as="form", extra=None):
    return [csrf_probe(url, cookie, token, token_field=token_field,
                       send_as=send_as, extra=extra)]
