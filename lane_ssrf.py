"""Lane SSRF — rileva la Server-Side Request Forgery (OWASP A10, offensiva).

Domanda: un parametro (una URL fornita dal client — webhook, fetcher di
immagini, importatore, anteprima link) viene usato dal server per fare una
*richiesta server-side* verso una destinazione che decide l'attaccante?

Metodo — il **canary locale**, l'analogo in-boundary dell'OAST (out-of-band):
ARIES avvia un minuscolo listener HTTP su `127.0.0.1:<porta effimera>` (quindi
dentro l'ALLOWLIST, mai un host esterno) e inietta nel parametro un URL che
punta a QUEL listener, con un **nonce** casuale nel path. Poi guarda se il
listener riceve una richiesta che porta il nonce.

  - il canary riceve il nonce  → il server ha fatto DAVVERO la richiesta verso
                                 una destinazione scelta dall'attaccante → SSRF
  - il canary non è contattato  → il server non ha seguito l'URL (validato/bloccato)

La prova è **oggettiva e out-of-band**, e vale anche per l'SSRF *cieca*: non
dipende da ciò che il server riflette nella risposta, ma dal fatto fisico che
il listener è stato colpito. Il nonce è casuale per run e la porta è effimera:
solo chi ha letto l'URL che abbiamo iniettato può colpire il canary con quel
nonce. Questo chiude il falso positivo dell'endpoint che fa semplicemente
l'**eco** dell'URL nel corpo della risposta (riflette la stringa ma NON la
richiede): quell'endpoint non colpisce mai il canary → la lane tace.

ATTIVO: manda una richiesta al bersaglio → SOLO host in ALLOWLIST (via
core.probe). Il canary è un servizio locale (127.0.0.1), non è il bersaglio.

Limite onesto: proviamo che il server fa una richiesta verso un URL arbitrario
scelto dal client (il cuore dell'SSRF). L'escalation concreta — leggere la
metadata del cloud (169.254.169.254), colpire servizi interni, esfiltrare —
dipende dalla rete del bersaglio e non viene assunta. Un server che fa un
redirect-follow o un DNS-rebinding sofisticato resta fuori da questo modello
minimale (una sola iniezione, un solo canary).
"""

import http.server
import secrets
import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core import finding, probe, as_curl


class _CanaryHandler(http.server.BaseHTTPRequestHandler):
    """Registra ogni richiesta ricevuta (qualunque metodo) e sveglia chi aspetta.
    Il path è ciò che ci interessa: deve contenere il nonce che abbiamo iniettato."""
    def log_message(self, *a):
        pass

    def _record(self):
        try:
            self.server.aries_hits.append(self.path)   # type: ignore[attr-defined]
            self.server.aries_event.set()              # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_HEAD = _record


def _start_canary():
    """Avvia il listener canary su 127.0.0.1:<porta effimera>. Ritorna
    (server, porta, event, hits). La porta 0 fa scegliere al kernel una porta
    libera: il bersaglio (locale) la raggiunge, l'esterno no."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), _CanaryHandler)
    srv.aries_hits = []                                # type: ignore[attr-defined]
    srv.aries_event = threading.Event()               # type: ignore[attr-defined]
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port, srv.aries_event, srv.aries_hits  # type: ignore[attr-defined]


def _inject(url, param, value, send_as):
    """Costruisce (url, headers, body) iniettando `value` nel parametro `param`,
    nei tre vettori tipici dell'SSRF: query (fetcher via GET), form, JSON
    (webhook/importatori via POST). Stessa forma degli altri lane attivi."""
    if send_as == "query":
        u = urlparse(url)
        q = parse_qs(u.query, keep_blank_values=True)
        q[param] = [value]
        full = urlunparse(u._replace(query=urlencode(q, doseq=True)))
        return full, {}, None
    if send_as == "form":
        return url, {"Content-Type": "application/x-www-form-urlencoded"}, urlencode({param: value})
    # json
    import json
    return url, {"Content-Type": "application/json"}, json.dumps({param: value})


def ssrf(url, param="url", send_as="query", method=None, wait=2.0, session=None):
    """Inietta un URL-canary locale nel parametro e verifica, out-of-band, se il
    server lo richiede davvero. Un solo canary, un solo nonce: la prova è il
    colpo ricevuto dal listener, non la risposta del bersaglio. `session`
    (Cookie/Bearer/header) raggiunge la superficie LOGGATA: un webhook/fetcher
    dietro l'autenticazione è invisibile senza la sessione (login wall). La
    sessione va al BERSAGLIO (in ALLOWLIST), non al canary locale."""
    if method is None:
        method = "GET" if send_as == "query" else "POST"
    srv, port, event, hits = _start_canary()
    try:
        nonce = secrets.token_hex(8)
        canary_url = f"http://127.0.0.1:{port}/ssrf-{nonce}"
        req_url, headers, body = _inject(url, param, canary_url, send_as)

        resp = probe(req_url, method, headers, body, session=session)
        if "error" in resp:
            return finding(f"ssrf:{param}", url, "ERRORE", "info",
                           "probe fallita", resp["error"])

        # Attesa limitata: con un fetch sincrono il colpo arriva prima che la
        # probe ritorni; il grace copre i server che fanno la richiesta async.
        event.wait(wait)
        got_nonce = any(nonce in h for h in hits)

        poc = as_curl(req_url, method, headers, body, session=session)
        if got_nonce:
            return finding(
                f"ssrf:{param}", url, "VULNERABILE (SSRF)", "high",
                "il server esegue una richiesta server-side verso un URL scelto dal "
                "client → SSRF (accesso a servizi interni / metadata cloud, a seconda "
                "della rete del bersaglio)",
                f"il canary locale 127.0.0.1:{port} ha ricevuto il nonce '{nonce}' "
                f"(param '{param}', {send_as}) → fetch server-side confermato out-of-band",
                poc)
        return finding(
            f"ssrf:{param}", url, "nessun fetch server-side", "ok",
            "l'URL iniettato NON è stato richiesto dal server (destinazione "
            "validata/bloccata, o il parametro non innesca un fetch): nessun colpo "
            "al canary",
            f"canary 127.0.0.1:{port} mai contattato con il nonce '{nonce}' "
            f"(param '{param}', {send_as})")
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass


def run(url, param="url", send_as="query", method=None, session=None):
    return [ssrf(url, param=param, send_as=send_as, method=method, session=session)]
