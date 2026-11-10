"""Lane CRLF — rileva la CRLF / HTTP Response Header Injection (CWE-113).

Domanda: un parametro il cui valore finisce in un **header di risposta** (il
caso canonico è `Location` di un redirect, ma anche `Set-Cookie` costruiti
dall'input) viene scritto GREZZO, così che una sequenza **CR-LF** nel valore
**spezzi** l'header e ne inietti uno nuovo scelto dall'attaccante? È il cuore
dell'HTTP response splitting: da lì cache-poisoning, Set-Cookie forgiati
(session fixation), o un corpo iniettato (XSS riflesso via split).

Metodo — **prova OGGETTIVA e STRUTTURALE**, non la riflessione. Iniettiamo nel
parametro un valore `<prefisso>CRLF X-Aries-Crlf: <nonce>` e poi guardiamo gli
**header della RISPOSTA**: se vi compare l'header `X-Aries-Crlf` col nostro
nonce, il server ha scritto il CR-LF grezzo in un header → l'ha **spezzato** e
ha materializzato l'header iniettato. Un endpoint che si limita a **riflettere**
il valore nel CORPO non produce mai un header di risposta → la lane tace: la
struttura della risposta È la guardia anti falso positivo (come il canary
dell'SSRF, il prodotto calcolato dell'SSTI, la firma del traversal). Il nonce è
casuale per run, così il match è attribuibile proprio alla nostra iniezione.

Proviamo due separatori: **CRLF** (`\\r\\n`, il classico) e **LF** solo
(`\\n`, alcuni parser spezzano anche senza il CR) — un filtro che toglie l'uno
ma non l'altro resta smascherato.

ATTIVO: manda richieste → SOLO host in allowlist (via core.probe). Il valore
iniettato resta nella richiesta verso lo stesso host autorizzato; nessun host
esterno è contattato.
"""

import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core import finding, probe, as_curl

# L'header-sentinella che proviamo a iniettare via CR-LF. Nome distintivo +
# nonce casuale: se riemerge come header di RISPOSTA, l'ha messo la nostra
# iniezione (nessun server lo emette spontaneamente).
_CANARY_HEADER = "X-Aries-Crlf"


def _with_param(url, param, value):
    """Rimpiazza (o aggiunge) un parametro nella query, preservando il resto.
    `urlencode` percent-codifica i caratteri di controllo (CR/LF → %0D%0A), così
    la richiesta è ben formata: è il SERVER a decodificarli e, se vulnerabile, a
    scriverli grezzi nell'header."""
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    q[param] = [value]
    return urlunparse(u._replace(query=urlencode(q, doseq=True)))


def _payloads(nonce):
    """Batteria di iniezioni: lo stesso header-sentinella dietro due separatori.
    Il prefisso è un valore di Location plausibile e benigno."""
    inj = f"{_CANARY_HEADER}: {nonce}"
    return [
        ("CRLF", f"/aries\r\n{inj}"),   # il separatore canonico CR-LF
        ("LF", f"/aries\n{inj}"),       # solo LF: alcuni parser spezzano lo stesso
    ]


def crlf(url, param="to", method="GET", session=None):
    """`session` (dict di header: Cookie / Bearer / custom) è instradata in ogni
    probe → raggiunge un endpoint DIETRO il login; il PoC la riporta MASCHERATA
    (`$TOKEN`/`$COOKIE`), il segreto non entra nel referto."""
    nonce = secrets.token_hex(4)
    for sep, pl in _payloads(nonce):
        target = _with_param(url, param, pl)
        resp = probe(target, method, session=session)
        if "error" in resp:
            return finding(f"crlf:{param}", url, "ERRORE", "info", "probe fallita", resp["error"])
        # La prova è STRUTTURALE: l'header-sentinella materializzato nella RISPOSTA
        # (gli header sono già lower-case in core.probe).
        got = resp.get("headers", {}).get(_CANARY_HEADER.lower())
        if got is not None and nonce in got:
            return finding(
                f"crlf:{param}", url, "VULNERABILE (CRLF header injection)", "high",
                "il parametro scrive CR-LF grezzo in un header di risposta → "
                "HTTP response splitting (header iniettati, cache-poisoning, Set-Cookie forgiati)",
                f"separatore {sep} → header INIETTATO '{_CANARY_HEADER}: {got}' nella risposta "
                f"(HTTP {resp.get('status')})",
                as_curl(target, method, session=session))
    return finding(f"crlf:{param}", url, "nessuna CRLF injection", "ok",
                   "il CR-LF iniettato non materializza un header di risposta "
                   "(valore neutralizzato o non scritto in un header)",
                   f"nessun header '{_CANARY_HEADER}' spezzato (param {param})")


def run(url, param="to", session=None):
    return [crlf(url, param=param, session=session)]
