"""Fixture VULNERABILE per validare la lane SQLi. Zero dipendenze (stdlib).

Due login, così il benchmark misura entrambe le facce:
  /login-vuln  → concatena l'input nella query  → SQL INJECTION (deve essere rilevata)
  /login-safe  → parametri legati (?, ?)        → IMMUNE       (NON deve essere segnalata)

È insicuro DI PROPOSITO. Gira SOLO su 127.0.0.1 — non esporlo mai.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import random
import sqlite3
import threading
import time
import urllib.request
import urllib.error
import xml.sax
from xml.sax.handler import feature_external_ges as _SAX_EXT_GES
from io import StringIO as _StringIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
_DB.execute("INSERT INTO users(username, password) VALUES('admin', 'secret')")
_DB.commit()


def _sql_sleep(seconds):                         # abilita il time-based blind sulla fixture
    time.sleep(min(float(seconds or 0), 6))      # cap di sicurezza
    return 0


_DB.create_function("sleep", 1, _sql_sleep)      # /login-vuln concatena → SLEEP(n) viene eseguita
_LOCK = threading.Lock()
_RL = {"n": 0}                                   # contatore per l'endpoint rate-limited
_LOCKOUT = {"n": 0}                              # contatore per la trappola /trap-auth-lockout
_DOCS = {"1": {"owner": "1", "data": "documento riservato di user 1"},
         "2": {"owner": "2", "data": "documento riservato di user 2"}}
_BASKETS = {"1": "basket di user 1", "2": "basket di user 2"}   # IDOR via Bearer + id nel path
_TOKENS = {"tok1": "1", "tok2": "2"}                             # token Bearer → utente
_RACE = {"vuln": False, "safe": False}           # flag "riscattato" per i due endpoint race
_CORS_TRUSTED = "https://trusted.example"        # unica origine in allowlist per /cors-safe
_SSRF_ALLOWED = {"img.trusted.example"}          # SSRF-safe: sole destinazioni che il fetch consente
_COMMENTS = {"vuln": [], "safe": []}             # stored-XSS: due bacheche persistite separate
_ACOMMENTS = {"vuln": [], "safe": []}            # stored-XSS DIETRO AUTH: bacheche riservate (scrittura+lettura gated)
# Superficie LOGGATA: gli endpoint /axss-* rispondono la pagina riservata SOLO a
# chi porta una sessione valida (cookie `sess=…`, Bearer o header X-Session) →
# senza sessione si vede il login wall (302), con la sessione la pagina vera.
# Serve a provare che `--cookie`/`--token`/`--header` instradati in core.probe
# raggiungono davvero la superficie dietro l'autenticazione.
SESSION_VALID = "s3cr3t-valid-sess"              # credenziale di sessione valida (cookie/Bearer/header)
# mass-assignment: profilo persistito, con una "colonna" server-controlled (role)
_PROFILE = {"vuln": {"name": "u1", "role": "user"},
            "safe": {"name": "u1", "role": "user"}}
_MA_COLUMNS = {"name", "role"}            # colonne del modello (una chiave ignota viene scartata)
_MA_SETTABLE = {"name"}                   # safe: SOLO questi campi sono client-settable (whitelist)
# Path Traversal / LFI: un filesystem VIRTUALE in memoria (nessun accesso al disco
# reale). Il docroot contiene file "pubblici"; /etc/passwd sta FUORI dalla radice e
# porta la firma oggettiva 'root:x:0:0:' che la lane cerca. Il /download-vuln fa join
# ingenuo + normpath (il '../' esce); il /download-safe riduce a basename (confinato).
_TRAV_DOCROOT = "/srv/app/public"
_TRAV_VFS = {
    "/srv/app/public/welcome.txt": "Benvenuto nella app demo.\n",
    "/srv/app/public/readme.txt": "File pubblico di esempio.\n",
    "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"),
}
# Path Traversal — bersaglio WINDOWS + troncatura NUL-byte legacy. Secondo
# filesystem virtuale, modellato con separatori '/' minuscoli (Windows è
# case-insensitive e tratta '\' ≡ '/'), chiavi col drive 'c:'. win.ini sta FUORI
# dalla radice e porta la firma oggettiva '[fonts]'/'[extensions]' che la lane
# cerca per il bersaglio Windows. L'endpoint vulnerabile modella un file-server
# legacy che (1) APPENDE un'estensione '.pdf' (serve solo fatture), (2) la stringa
# finisce in una open() C che TRONCA al primo NUL → un '%00' nel payload taglia
# l'estensione appesa e scopre win.ini; (3) fa join INGENUO stile Windows → il
# traversal '..\' esce dalla radice. Il safe riduce a basename (confinato).
_TRAV_WIN_DOCROOT = "c:/inetpub/invoices"
_TRAV_WIN_VFS = {
    "c:/inetpub/invoices/welcome.pdf": "%PDF-1.4 fattura demo (file pubblico)\n",
    "c:/windows/win.ini": ("; for 16-bit app support\n[fonts]\n[extensions]\n"
                           "[mci extensions]\n[files]\n[Mail]\nMAPI=1\n"),
}


def _win_resolve(docroot, name):
    """Modella un join di path Windows INGENUO su host Windows: '\\' ≡ '/',
    case-insensitive (lower), risolve i '..' SENZA riconfinare (il traversal
    esce), riconosce i path assoluti ('C:\\...' o '\\...'). Ritorna il path
    assoluto normalizzato col drive, da cercare in `_TRAV_WIN_VFS`.
    os.path su Linux È posixpath → normpath su path assoluto clampa i '..' in
    eccesso alla radice (come fa il docroot Unix con os.path.join)."""
    n = name.replace("\\", "/").lower()
    m = _re.match(r"^([a-z]:)(.*)$", n)          # path assoluto con drive (C:/...)
    if m:
        drive, rest = m.group(1), m.group(2)
        if not rest.startswith("/"):
            rest = "/" + rest
        return drive + os.path.normpath(rest)
    dm = _re.match(r"^([a-z]:)(/.*)$", docroot)  # drive + path del docroot
    drive, droot = dm.group(1), dm.group(2)
    if n.startswith("/"):                         # assoluto senza drive → drive del docroot
        return drive + os.path.normpath(n)
    return drive + os.path.normpath(droot + "/" + n)
# LFI via php://filter (SOURCE DISCLOSURE): un'app PHP-like fa `include($_GET['page'])`.
# Un include "normale" ESEGUE lo script (niente sorgente a video); il wrapper
# php://filter/convert.base64-encode/resource=<f> forza lo stream a restituire la
# SORGENTE del file in base64 (che l'attaccante decodifica offline). Le "sorgenti"
# virtuali portano un tag PHP `<?php` + un segreto hardcoded, il bersaglio tipico.
_LFI_SOURCES = {
    "index.php": ("<?php\n"
                  "// entry point dell'app demo\n"
                  "define('DB_DSN', 'mysql:host=127.0.0.1;dbname=app');\n"
                  "$admin_pw = 'S3cr3tDbPw!';\n"
                  "include($_GET['page'] . '.php');\n"),
    "config.php": ("<?php\n"
                   "define('DB_USER', 'admin');\n"
                   "define('DB_PASS', 'S3cr3tDbPw!');\n"
                   "define('API_KEY', 'sk_live_deadbeef');\n"),
}


# CSRF: la sessione autenticata (cookie) e il token anti-CSRF valido che la lane invia
CSRF_COOKIE = "session=sess_valid_123"           # autorità ambientale: il cookie di sessione
CSRF_TOKEN = "csrf_good_token"                    # token anti-CSRF valido (quello della pagina legittima)

# --- SSTI: un mini "motore di template" che VALUTA le espressioni {{N*M}} ----
import re as _re
_TPL_EXPR = _re.compile(r"\{\{\s*(\d+)\s*([*+])\s*(\d+)\s*\}\}")


def _tpl_render(s):
    """Interpola come farebbe un motore di template vulnerabile: sostituisce
    ogni `{{N*M}}`/`{{N+M}}` col risultato calcolato. Niente eval reale: solo
    aritmetica intera su interi, abbastanza per modellare la valutazione SSTI."""
    def _ev(m):
        x, op, y = int(m.group(1)), m.group(2), int(m.group(3))
        return str(x * y if op == "*" else x + y)
    return _TPL_EXPR.sub(_ev, s)


# --- LFI via php://filter: modella un `include($_GET['page'])` PHP-like --------
_LFI_FILTER = _re.compile(
    r"^php://filter/(?:read=)?convert\.base64-encode/resource=(.+)$")

# --- LFI via data:// wrapper (RCE): include + ESECUZIONE di uno stream esterno --
# `data:[<mime>][;base64],<payload>` — con allow_url_include=On, PHP include lo
# stream e, se contiene `<?php…?>`, lo ESEGUE. Modelliamo l'esecuzione valutando
# gli `echo` (stringhe letterali + aritmetica intera), come `_tpl_render` modella
# la valutazione SSTI: niente eval reale, solo l'output deterministico del codice.
_LFI_DATA = _re.compile(r"^data:(?://)?[^,]*,(.*)$", _re.S)
_PHP_ECHO = _re.compile(r"echo\s+(?:'([^']*)'|\"([^\"]*)\"|(\d+)\s*([*+])\s*(\d+))")


def _php_exec(code):
    """Modella l'ESECUZIONE del PHP incluso via data:// (allow_url_include=On):
    estrae il blocco `<?php…?>` e concatena l'output degli `echo` — stringhe
    letterali e un'aritmetica intera (`N*M`/`N+M`). Deterministico, nessun eval."""
    m = _re.search(r"<\?php(.*?)\?>", code, _re.S)
    body = m.group(1) if m else code
    out = []
    for em in _PHP_ECHO.finditer(body):
        if em.group(1) is not None:
            out.append(em.group(1))
        elif em.group(2) is not None:
            out.append(em.group(2))
        else:
            x, op, y = int(em.group(3)), em.group(4), int(em.group(5))
            out.append(str(x * y if op == "*" else x + y))
    return "".join(out)


def _rce_data_render(page, safe):
    """Modella `include($_GET['page'])` di un'app PHP con allow_url_include=On.
    A differenza di `_lfi_render` (che modella la source-disclosure php://filter),
    QUI il vettore è il wrapper `data://`, che fa INCLUDERE ed ESEGUIRE lo stream
    scelto dal client → RCE. Endpoint SEPARATO apposta: così il verdetto
    VULNERABILE è ATTRIBUIBILE al solo data:// (non alla php://filter dell'altro
    fixture), e la lane prova davvero la detection data://.
      VULN: esegue lo stream data:// (il prodotto PHP incorporato compare).
      SAFE: lo schema data:// è bloccato → nessuna esecuzione (serve le pagine)."""
    m = _LFI_DATA.match(page)
    if m:
        if safe:
            return "Errore: schema non consentito.\n"     # data:// bloccato
        raw = m.group(1)
        if ";base64" in page.split(",", 1)[0]:            # payload base64 → decodifica
            try:
                raw = base64.b64decode(raw).decode("utf-8", "replace")
            except Exception:
                return "Warning: include(): failed to open stream.\n"
        return _php_exec(raw)                              # stream INCLUSO ed ESEGUITO
    # include "normale": esegue la pagina → output renderizzato (mai sorgente/RCE).
    page_name = _re.split(r"[\\/]", page)[-1] or "home"
    return f"<html><body><h1>Pagina: {html.escape(page_name)}</h1></body></html>\n"


def _lfi_render(page, safe):
    """Modella `include($_GET['page'])` di PHP.
      VULN: supporta il wrapper php://filter/convert.base64-encode/resource=<f> →
        emette la SORGENTE del file codificata base64 (la source-disclosure). Un
        include "normale" invece ESEGUE lo script → output renderizzato, mai la
        sorgente (ecco perché serve il wrapper).
      SAFE: rifiuta lo schema php:// → nessuna sorgente svelata, ma serve le pagine
        legittime (non rifiuta tutto)."""
    m = _LFI_FILTER.match(page)
    if m:
        if safe:
            # SICURO: lo schema php:// è bloccato → nessuna disclosure.
            return "Errore: schema non consentito.\n"
        res = _re.split(r"[\\/]", m.group(1))[-1]        # basename del resource
        src = _LFI_SOURCES.get(res)
        if src is not None:
            return base64.b64encode(src.encode()).decode()
        return "Warning: include(): failed to open stream.\n"
    # include "normale": esegue la pagina → output RENDERIZZATO, mai la sorgente.
    page_name = _re.split(r"[\\/]", page)[-1] or "home"
    return f"<html><body><h1>Pagina: {html.escape(page_name)}</h1></body></html>\n"


# --- NoSQLi: un mini "matcher" stile MongoDB che VALUTA gli operatori --------
def _mongo_match(cond, stored):
    """Simula il matching di MongoDB di un valore `stored` contro una condizione
    `cond`. Se `cond` è un dict di operatori li VALUTA (ecco perché gli operatori
    iniettati nel body bypassano l'autenticazione su /nosqli-vuln); altrimenti è
    un confronto di uguaglianza. Abbastanza per modellare l'operator-injection."""
    if isinstance(cond, dict):
        for op, val in cond.items():
            if op == "$ne":
                if not (stored != val):
                    return False
            elif op == "$eq":
                if not (stored == val):
                    return False
            elif op == "$gt":
                if not (str(stored) > str(val)):
                    return False
            elif op == "$in":
                if stored not in (val if isinstance(val, list) else []):
                    return False
            elif op == "$regex":
                if _re.search(str(val), str(stored)) is None:
                    return False
            else:
                return False                         # operatore ignoto → no match
        return True
    return str(stored) == str(cond)


def _parse_bracket(raw):
    """Modella il parsing 'extended' di Express (qs/body-parser) e di PHP: una
    chiave form-urlencoded `campo[$op]=val` diventa un dict ANNIDATO
    {campo: {$op: val}} — ecco perché un operatore Mongo passato in
    bracket-notation (fuori dal body JSON) RAGGIUNGE la query su /nosqli-br-vuln."""
    out = {}
    for k, v in parse_qs(raw.decode("utf-8", "replace")).items():
        m = _re.match(r"^([^\[\]]+)\[([^\[\]]+)\]$", k)
        if m:
            out.setdefault(m.group(1), {})[m.group(2)] = v[0]
        else:
            out[k] = v[0]
    return out


# --- JWT: due endpoint protetti da Bearer, uno fragile e uno robusto --------
def _jb64d(s):
    return base64.urlsafe_b64decode(s.encode() + b"=" * (-len(s) % 4))


def _jb64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt_make(payload, secret, alg="HS256"):     # token HS256 valido (per i test)
    h = _jb64e(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = _jb64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _jb64e(hmac.new(secret.encode(), (h + "." + p).encode(), hashlib.sha256).digest())
    return h + "." + p + "." + sig


def _jwt_verify(token, secret, *, allow_none, check_exp):
    """Verifica un JWT HS256. `allow_none`/`check_exp` modellano le due facce."""
    try:
        hb, pb, sb = token.split(".")
        header = json.loads(_jb64d(hb))
        payload = json.loads(_jb64d(pb))
    except Exception:
        return None
    if str(header.get("alg", "")).lower() == "none":
        if not allow_none:
            return None                          # SICURO: alg=none respinto
        # VULNERABILE: accetta senza controllare la firma
    else:
        want = _jb64e(hmac.new(secret.encode(), (hb + "." + pb).encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(want, sb):
            return None
    if check_exp:
        exp = payload.get("exp")
        try:
            if exp is not None and float(exp) < time.time():
                return None                      # SICURO: token scaduto respinto
        except (TypeError, ValueError):
            return None
    return payload


_JWT_VULN_SECRET = "secret"                      # debole: è nella wordlist → crackabile
_JWT_SAFE_SECRET = "Kp9$vX2mWq7zR4tL8nJ3bH6yG1cF5dS0aUoEiZxPwMnQrTv"   # lungo/casuale, NON in wordlist
# Token legittimi che l'utente già possiede (la lane jwt parte da uno di questi):
VALID_TOKEN_VULN = _jwt_make({"sub": "1", "role": "user"}, _JWT_VULN_SECRET)
VALID_TOKEN_SAFE = _jwt_make({"sub": "1", "role": "user", "exp": int(time.time()) + 3600},
                             _JWT_SAFE_SECRET)


# --- SSRF: un "fetcher" server-side (es. anteprima link / import da URL) -----
def _ssrf_fetch(target):
    """Esegue DAVVERO una richiesta server-side verso `target` (è ciò che rende
    SSRF il /ssrf-vuln). Cap su tempo e byte per sicurezza; gira solo in locale
    dentro il benchmark. Ritorna (status, corpo-troncato) o solleva."""
    req = urllib.request.Request(target, method="GET")
    try:
        r = urllib.request.urlopen(req, timeout=3)
        return r.status, r.read(512)
    except urllib.error.HTTPError as e:
        return e.code, e.read(512)


def _authed(headers):
    """La sessione è valida se la richiesta porta la credenziale per UNA delle
    tre vie instradabili dai flag CLI: Cookie `sess=…`, Authorization: Bearer, o
    header custom X-Session. Modella un'area riservata: senza una di queste →
    non autenticato."""
    if f"sess={SESSION_VALID}" in headers.get("Cookie", ""):
        return True
    if headers.get("Authorization", "") == f"Bearer {SESSION_VALID}":
        return True
    if headers.get("X-Session", "") == SESSION_VALID:
        return True
    return False


# --- Fixture GraphQL per la lane `graphql` ----------------------------------
# Mini-endpoint GraphQL modellato a mano (nessun motore reale → deterministico,
# zero dipendenze). Le due facce differiscono SOLO nella configurazione delle tre
# debolezze: introspezione, field-suggestion e batching.
_GQL_SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [{"name": n} for n in
              ("Query", "Mutation", "User", "SecretConfig", "AuthToken")],
}


def _graphql_handle(body, vuln):
    """Risposta del mini-endpoint GraphQL → (codice, oggetto).
      - body LISTA  → richiesta di BATCH: il vuln esegue tutte le query e
        restituisce una LISTA di N risultati; il safe NON fa batch → un singolo
        oggetto errore (non una lista).
      - body con `__schema` → introspezione: il vuln rende lo schema completo;
        il safe risponde con un errore (introspezione disabilitata).
      - campo sconosciuto (typo) → il vuln suggerisce il campo reale ('Did you
        mean …'); il safe dà l'errore SENZA suggerimento.
      - `{__typename}` → meta-campo valido su ogni endpoint GraphQL."""
    if isinstance(body, list):
        if vuln:
            # BATCHING ABILITATO: esegue tutte le query → lista di N risultati
            return 200, [{"data": {"__typename": "Query"}} for _ in body]
        # SICURO: batching non supportato → un SINGOLO oggetto errore (non lista)
        return 200, {"errors": [{"message": "batch queries are not supported"}]}
    q = str(body.get("query", "")) if isinstance(body, dict) else ""
    if "__schema" in q:
        if vuln:
            # INTROSPECTION ESPOSTA: lo schema completo è restituito
            return 200, {"data": {"__schema": _GQL_SCHEMA}}
        # SICURO: introspezione disabilitata → errore, nessun data.__schema
        return 200, {"errors": [{"message": "GraphQL introspection is disabled"}]}
    field = q.strip().strip("{}").strip()
    if field == "__typename":
        return 200, {"data": {"__typename": "Query"}}
    # campo sconosciuto (il typo `__typenam` del test di suggestion)
    if vuln:
        # SUGGESTION ATTIVA: suggerisce il campo reale più vicino
        hint = "__typename" if field.startswith("__typ") else "me"
        return 200, {"errors": [{"message":
            f'Cannot query field "{field}" on type "Query". Did you mean "{hint}"?'}]}
    # SICURO: nessun suggerimento (solo l'errore secco)
    return 200, {"errors": [{"message":
        f'Cannot query field "{field}" on type "Query".'}]}


# --- XXE: parsing XML con/senza risoluzione delle entità esterne ------------
class _XxeChars(xml.sax.ContentHandler):
    """Raccoglie il TESTO (char data) dei nodi. Quando il parser risolve
    un'entità esterna SYSTEM `file://`, il contenuto del file arriva qui come
    testo → finisce nella risposta (è esattamente l'XXE)."""
    def __init__(self):
        self._buf = []

    def characters(self, content):
        self._buf.append(content)

    def text(self):
        return "".join(self._buf)


def _xxe_parse(xml_text, resolve_external):
    """Parsa `xml_text` e ritorna il testo dei nodi. `resolve_external` è
    l'interruttore che SEPARA il vulnerabile dal sicuro, un fatto del parser
    (non una stringa riflessa):
      - True  (VULN) → `feature_external_ges` ON: expat risolve le entità esterne
        SYSTEM (`file:///etc/passwd` → contenuto del file nel testo) = XXE;
      - False (SAFE) → l'external-entity processing è DISABILITATO, la difesa
        CANONICA contro l'XXE → l'entità non è espansa, il file non viene letto.
    L'eccezione di parsing è catturata dal chiamante (un XML malformato → corpo
    vuoto, il safe tace comunque)."""
    h = _XxeChars()
    p = xml.sax.make_parser()
    p.setFeature(_SAX_EXT_GES, bool(resolve_external))
    p.setContentHandler(h)
    p.parse(_StringIO(xml_text))
    return h.text()


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _fields(self):
        """Legge i campi del corpo sia form-urlencoded sia JSON (serve al CSRF,
        che è classicamente form-based ma la lane supporta anche JSON)."""
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                return json.loads(raw or b"{}")
            except Exception:
                return {}
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def _reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _trap_text(self, text):
        """Risposta 200 testuale (eco verbatim/latenza): riflette `text` grezzo,
        senza eseguirlo né valutarlo. Usata dalle trappole del banco avversariale."""
        body = text.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _trap_spa(self):
        """Risposta 200 COSTANTE stile SPA (stessa per ogni metodo/parametro): non
        riflette nulla dell'input. Usata dalle trappole del banco avversariale."""
        body = b"<!doctype html><html><body><div id=app>Caricamento...</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/graphql-vuln" or p.path == "/graphql-safe":
            # Transport GET di GraphQL (`?query=…`). Due facce SOLO sulla CSRF da
            # mutation (il resto — introspection/suggestion/batching — resta su POST):
            #   - VULN → esegue QUALUNQUE operazione via GET, MUTATION comprese →
            #     `mutation{__typename}` è eseguita e restituisce il tipo radice;
            #   - SAFE → vieta le MUTATION su GET (405, solo POST), ma ammette le
            #     query in sola lettura via GET (best practice OWASP: caching).
            # L'operazione viaggia nella query-string, non nel corpo.
            q = (parse_qs(p.query).get("query") or [""])[0]
            is_mut = q.lstrip().startswith("mutation")
            if p.path.endswith("-safe") and is_mut:
                return self._reply(405, {"errors": [{"message":
                    "Can only perform a mutation operation from a POST request."}]})
            root = "Mutation" if is_mut else "Query"
            return self._reply(200, {"data": {"__typename": root}})
        if self.path.startswith("/jwt-vuln") or self.path.startswith("/jwt-safe"):
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            if self.path.startswith("/jwt-vuln"):     # accetta alg=none, chiave debole, ignora exp
                payload = _jwt_verify(tok, _JWT_VULN_SECRET, allow_none=True, check_exp=False)
            else:                                      # verifica firma forte, alg fisso, exp
                payload = _jwt_verify(tok, _JWT_SAFE_SECRET, allow_none=False, check_exp=True)
            if payload is None:
                return self._reply(401, {"error": "token non valido"})
            return self._reply(200, {"ok": True, "sub": payload.get("sub")})
        if self.path.startswith("/doc-vuln") or self.path.startswith("/doc-safe"):
            did = (parse_qs(p.query).get("id") or ["0"])[0]
            doc = _DOCS.get(did)
            if not doc:
                return self._reply(404, {"error": "not found"})
            if self.path.startswith("/doc-safe") and self.headers.get("X-User", "") != doc["owner"]:
                return self._reply(403, {"error": "forbidden"})   # ownership check
            return self._reply(200, {"id": did, "data": doc["data"]})  # vuln: nessun check
        if self.path.startswith("/basket-vuln/") or self.path.startswith("/basket-safe/"):
            bid = p.path.rstrip("/").rsplit("/", 1)[-1]            # id dal PATH
            auth = self.headers.get("Authorization", "")
            owner = _TOKENS.get(auth[7:] if auth.startswith("Bearer ") else "")
            if not owner:
                return self._reply(401, {"error": "token mancante/ignoto"})
            if bid not in _BASKETS:
                return self._reply(404, {"error": "not found"})
            if self.path.startswith("/basket-safe/") and owner != bid:
                return self._reply(403, {"error": "forbidden"})   # ownership check (safe)
            return self._reply(200, {"id": bid, "data": _BASKETS[bid]})  # vuln: nessun check
        if self.path.startswith("/redirect-vuln") or self.path.startswith("/redirect-safe"):
            to = (parse_qs(p.query).get("to") or [""])[0]
            if self.path.startswith("/redirect-safe"):
                tp = urlparse(to)                 # SICURO: solo path interni relativi
                if tp.scheme or tp.netloc or not to.startswith("/"):
                    return self._reply(400, {"error": "redirect non consentito"})
            self.send_response(302)               # vuln: rispedisce ovunque dica 'to'
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/crlf-vuln") or self.path.startswith("/crlf-safe"):
            # CRLF / HTTP response header injection: il valore di `to` finisce
            # nell'header Location. Il VULN lo scrive GREZZO → un CR-LF nel valore
            # spezza l'header e ne inietta uno nuovo; il SAFE neutralizza CR/LF
            # prima di scriverlo (difesa canonica) → nessuna iniezione.
            to = (parse_qs(p.query).get("to") or [""])[0]
            if self.path.startswith("/crlf-safe"):
                to = to.replace("\r", "").replace("\n", "")
            self.send_response(302)
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/cors-vuln") or self.path.startswith("/cors-safe"):
            origin = self.headers.get("Origin", "")
            body = json.dumps({"data": "profilo riservato di user 1"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if self.path.startswith("/cors-vuln"):
                # VULNERABILE: riflette QUALSIASI Origin e abilita le credenziali
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
            else:
                # SICURO: riflette solo l'origine in allowlist; le altre senza header CORS
                if origin == _CORS_TRUSTED:
                    self.send_header("Access-Control-Allow-Origin", _CORS_TRUSTED)
                    self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/cors-preflight-vuln") or self.path.startswith("/cors-preflight-safe"):
            # La GET semplice NON porta header CORS: la debolezza (o la sua
            # assenza) vive SOLO nel preflight OPTIONS → vedi do_OPTIONS.
            body = json.dumps({"data": "profilo riservato di user 1"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/dom-vuln") or self.path.startswith("/dom-safe"):
            sink = "innerHTML" if self.path.startswith("/dom-vuln") else "textContent"
            page = ("<!doctype html><html><body><div id=out></div><script>"
                    "var x=new URLSearchParams(location.search).get('x')||'';"
                    f"document.getElementById('out').{sink}=x;"
                    "</script></body></html>")
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssti-vuln") or self.path.startswith("/ssti-safe"):
            name = (parse_qs(p.query).get("q") or [""])[0]
            if self.path.startswith("/ssti-vuln"):
                # VULNERABILE: l'input passa per il motore di template → {{…}} valutato
                page = f"<html><body><p>Ciao {_tpl_render(name)}</p></body></html>"
            else:
                # SICURO: l'input è riflesso COME DATO, mai interpretato come template
                page = f"<html><body><p>Ciao {html.escape(name)}</p></body></html>"
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/comments-vuln") or self.path.startswith("/comments-safe"):
            store = "vuln" if self.path.startswith("/comments-vuln") else "safe"
            if store == "vuln":
                # VULNERABILE: i commenti persistiti sono resi CRUDI nell'HTML → stored XSS
                items = "".join(f"<li>{c}</li>" for c in _COMMENTS["vuln"])
            else:
                # SICURO: ogni commento è escapato come DATO prima di finire nell'HTML
                items = "".join(f"<li>{html.escape(c)}</li>" for c in _COMMENTS["safe"])
            page = f"<html><body><ul>{items}</ul></body></html>"
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/acomments-vuln") or self.path.startswith("/acomments-safe"):
            # Stored-XSS DIETRO AUTH (LETTURA della bacheca riservata). Senza
            # sessione → login wall a corpo COSTANTE (nessun commento reso): il
            # canary scritto non riemerge → la lane stored-xss TACE (no FP, come
            # Auth-XSS/Auth-SQLi). Con la sessione instradata in core.probe → la
            # bacheca vera, resa CRUDA nel vuln (stored XSS) / ESCAPATA nel safe.
            if not _authed(self.headers):
                body = b"<html><body>Bacheca riservata. <a href='/login'>login</a></body></html>"
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            store = "vuln" if self.path.startswith("/acomments-vuln") else "safe"
            if store == "vuln":
                items = "".join(f"<li>{c}</li>" for c in _ACOMMENTS["vuln"])          # CRUDO → stored XSS
            else:
                items = "".join(f"<li>{html.escape(c)}</li>" for c in _ACOMMENTS["safe"])  # escapato
            page = f"<html><body><ul>{items}</ul></body></html>"
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/profile-vuln") or self.path.startswith("/profile-safe"):
            # mass-assignment: la LETTURA rende lo stato persistito del profilo
            store = "vuln" if self.path.startswith("/profile-vuln") else "safe"
            return self._reply(200, _PROFILE[store])
        if self.path.startswith("/ssrf-vuln") or self.path.startswith("/ssrf-safe"):
            # SSRF: il parametro `url` è l'indirizzo di un "fetcher" server-side.
            to = (parse_qs(p.query).get("url") or [""])[0]
            if self.path.startswith("/ssrf-safe"):
                # SICURO: fetch SOLO verso una destinazione in allowlist; qualsiasi
                # altro host (compreso il canary 127.0.0.1) è rifiutato → nessun fetch.
                if (urlparse(to).hostname or "") not in _SSRF_ALLOWED:
                    return self._reply(400, {"error": "destinazione non consentita"})
            # VULNERABILE (/ssrf-vuln): segue l'URL del client ovunque punti.
            try:
                status, _ = _ssrf_fetch(to)
                return self._reply(200, {"fetched": True, "upstream_status": status})
            except Exception as e:
                return self._reply(502, {"error": f"fetch fallito: {e}"})
        if self.path.startswith("/download-vuln") or self.path.startswith("/download-safe"):
            # Path Traversal: il parametro `file` è un nome di file da servire.
            fname = (parse_qs(p.query).get("file") or [""])[0]
            if self.path.startswith("/download-safe"):
                # SICURO: scarta ogni componente di path (basename) → mai fuori radice.
                fname = os.path.basename(fname)
            # VULNERABILE: join ingenuo del nome fornito dal client alla radice; il
            # normpath risolve i '../' MA non riconfina il risultato → esce dalla radice.
            full = os.path.normpath(os.path.join(_TRAV_DOCROOT, fname))
            content = _TRAV_VFS.get(full)
            if content is None:
                return self._reply(404, {"error": "file non trovato"})
            body = content.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/wdownload-vuln") or self.path.startswith("/wdownload-safe"):
            # Path Traversal bersaglio WINDOWS + troncatura NUL-byte legacy.
            raw = (parse_qs(p.query).get("file") or [""])[0]
            if self.path.startswith("/wdownload-safe"):
                # SICURO: Windows-basename (ultimo componente dopo / o \), NUL via
                # troncatura ma poi confinato alla radice → mai fuori docroot.
                base = _re.split(r"[\\/]", raw.split("\x00", 1)[0])[-1]
                full = _TRAV_WIN_DOCROOT + "/" + (base + ".pdf").lower()
            else:
                # VULNERABILE: l'app serve solo '.pdf' → appende l'estensione; la
                # stringa passa per una open() C che TRONCA al primo NUL (un '%00'
                # nel payload taglia '.pdf' e scopre win.ini); join ingenuo → esce.
                appended = raw + ".pdf"
                truncated = appended.split("\x00", 1)[0]       # troncatura NUL legacy
                full = _win_resolve(_TRAV_WIN_DOCROOT, truncated)
            content = _TRAV_WIN_VFS.get(full)
            if content is None:
                return self._reply(404, {"error": "file non trovato"})
            body = content.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/lfi-vuln") or self.path.startswith("/lfi-safe"):
            # LFI via php://filter: il parametro `page` è il file da includere.
            # VULN: supporta il wrapper php://filter → svela la sorgente base64.
            # SAFE: blocca lo schema php:// → nessuna disclosure (serve le pagine).
            page = (parse_qs(p.query).get("page") or [""])[0]
            body = _lfi_render(page, safe=self.path.startswith("/lfi-safe")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/rce-data-vuln") or self.path.startswith("/rce-data-safe"):
            # LFI via data:// wrapper (RCE): il parametro `page` è lo stream da
            # includere. VULN: allow_url_include=On → lo stream data:// è INCLUSO
            # ed ESEGUITO (il prodotto del PHP incorporato compare). SAFE: schema
            # data:// bloccato → nessuna esecuzione.
            page = (parse_qs(p.query).get("page") or [""])[0]
            body = _rce_data_render(page, safe=self.path.startswith("/rce-data-safe")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/cookie-weak") or self.path.startswith("/cookie-strong"):
            # SameSite CSRF-defense (check passivo): entrambi impostano un cookie
            # di sessione con Secure+HttpOnly (quindi `cookie-flags` li vede
            # "robusti"), ma il VALORE di SameSite cambia la difesa CSRF:
            #   weak   → SameSite=None  → NESSUNA difesa (il buco storico)
            #   strong → SameSite=Lax   → difesa presente
            weak = self.path.startswith("/cookie-weak")
            cookie = "session=sess_abc; Secure; HttpOnly; SameSite=" + ("None" if weak else "Lax")
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/hsts-weak") or self.path.startswith("/hsts-strong"):
            # HSTS value-aware (check passivo): entrambi IMPOSTANO l'header
            # Strict-Transport-Security (quindi il controllo di PRESENZA li vede
            # "presente"), ma il VALORE di max-age cambia la difesa reale:
            #   weak   → max-age=0            → HSTS DISATTIVATO (il browser dimentica)
            #   strong → max-age=31536000…    → HSTS attivo
            weak = self.path.startswith("/hsts-weak")
            hsts = "max-age=0" if weak else "max-age=31536000; includeSubDomains"
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Strict-Transport-Security", hsts)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/csp-weak") or self.path.startswith("/csp-strong"):
            # CSP value-aware (check passivo): entrambi IMPOSTANO l'header
            # Content-Security-Policy (quindi il controllo di PRESENZA li vede
            # "presente/ok"), ma il VALORE cambia la difesa reale contro l'XSS:
            #   weak   → script-src 'unsafe-inline' (senza nonce) → inline esegue → INERTE
            #   strong → script-src con un nonce (no 'unsafe-inline')          → inline bloccato
            weak = self.path.startswith("/csp-weak")
            csp = ("default-src 'self'; script-src 'self' 'unsafe-inline'" if weak
                   else "default-src 'self'; script-src 'self' 'nonce-r4nd0m2024'")
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Security-Policy", csp)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/xcto-weak") or self.path.startswith("/xcto-strong"):
            # X-Content-Type-Options value-aware (check passivo): entrambi IMPOSTANO
            # l'header (il controllo di PRESENZA li vede "presente"), ma solo
            # `nosniff` disabilita il MIME-sniffing:
            #   weak   → `none`    → valore inerte, il browser continua a sniffare
            #   strong → `nosniff` → MIME-sniffing disabilitato
            weak = self.path.startswith("/xcto-weak")
            xcto = "none" if weak else "nosniff"
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", xcto)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/xfo-weak") or self.path.startswith("/xfo-strong"):
            # X-Frame-Options value-aware (check passivo): entrambi IMPOSTANO
            # l'header (il controllo di PRESENZA li vede "presente"), ma solo
            # `DENY`/`SAMEORIGIN` difendono dal clickjacking:
            #   weak   → `ALLOW-FROM …` → deprecato, ignorato dai browser → inerte
            #   strong → `DENY`         → framing ostile vietato
            weak = self.path.startswith("/xfo-weak")
            xfo = "ALLOW-FROM https://trusted.example" if weak else "DENY"
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Frame-Options", xfo)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # --- BANCO AVVERSARIALE: trappole "sane ma ingannevoli" (3ª faccia) -----
        # Endpoint NON vulnerabili che SOMIGLIANO a esserlo: servono al self-check
        # `_adversarial_selfcheck` del bench, che punta ogni lane coperta contro la
        # trappola corrispondente e pretende SILENZIO (verdetto non-VULNERABILE).
        # Nessuno di questi esegue/valuta/include/fetcha l'input: lo riflette e basta.
        if self.path.startswith("/trap-echo"):
            # ECO VERBATIM: riflette i valori dei parametri di query NEL CORPO, grezzi
            # (non in header di sicurezza, non eseguiti). Trappola per SQLi (nessun
            # errore SQL, TRUE/FALSE eguale-lunghezza), SSTI (payload letterale, mai
            # il prodotto), SSRF (URL riflesso ma mai richiesto → canary non colpito),
            # redirect (nessun 3xx/Location), traversal (nessuna firma di file).
            vals = parse_qs(p.query, keep_blank_values=True)
            echo = " ".join(v for vs in vals.values() for v in vs)
            self._trap_text("ECHO: " + echo)
            return
        if self.path.startswith("/trap-spa"):
            # 200-A-TUTTO stile SPA: stesso corpo COSTANTE per ogni metodo/parametro,
            # nessuna riflessione dell'input. Trappola per XSS (canary non riflesso),
            # NoSQLi/CSRF (baseline/true/false o A/C/D tutti identici → nessun
            # differenziale), stored-XSS (canary mai riemerso), JWT (firma non
            # verificata → accettazione non attribuibile, serve la guardia negativa).
            self._trap_spa()
            return
        if self.path.startswith("/trap-id-echo"):
            # ID-ECHO / APERTO: 200 a QUALUNQUE id (anche inesistente), con l'id
            # RIFLESSO nel corpo + un guscio costante. NON è una risorsa per-id
            # memorizzata: serve lo stesso guscio per ogni id, variando solo per
            # l'id riflesso. Trappola per IDOR: owned/other danno corpi che
            # DIFFERISCONO (per il solo id) → la 1ª guardia (corpi identici) NON
            # scatta; ma la 2ª guardia (sonda nonce) chiede un id inesistente, che
            # qui dà comunque 200 → la lane riconosce l'endpoint aperto e TACE.
            # Funziona sia in query (`?id=`) sia in path (`/trap-id-echo/<id>`).
            tail = p.path.rstrip("/").rsplit("/", 1)[-1]
            rid = tail if tail != "trap-id-echo" else (parse_qs(p.query).get("id") or ["0"])[0]
            return self._reply(200, {"id": rid, "shell": "Caricamento..."})
        if self.path.startswith("/trap-headers"):
            # ECO DEGLI HEADER di richiesta (Origin/Authorization) NEL CORPO, mai nei
            # corrispondenti header di risposta (nessun ACAO/ACAC). Trappola per CORS:
            # l'Origin arbitrario è riflesso nel corpo ma NON in Access-Control-Allow-Origin.
            obj = {"origin": self.headers.get("Origin", ""),
                   "authorization": self.headers.get("Authorization", ""), "ok": True}
            return self._reply(200, obj)
        if self.path.startswith("/trap-latency"):
            # LATENZA CASUALE ma SOTTO-SOGLIA (jitter di rete): corpo costante dopo un
            # piccolo ritardo casuale. Trappola per il time-based SQLi: il ritardo non
            # segue mai il valore iniettato e resta ben sotto la soglia di rilevazione.
            time.sleep(random.uniform(0, 0.12))
            self._trap_text("ok")
            return
        if self.path.startswith("/axss-vuln") or self.path.startswith("/axss-safe"):
            # Superficie LOGGATA: senza sessione valida → login wall (302), nessun
            # riflesso, banner sobrio. Con la sessione → pagina riservata che
            # riflette `q` (RAW nel vuln → XSS; escapato nel safe) e un banner
            # verboso (così `check` dietro-auth legge gli header della pagina VERA).
            if not _authed(self.headers):
                body = b"<html><body>Accesso riservato. <a href='/login'>login</a></body></html>"
                self.send_response(302)
                self.send_header("Location", "/login")       # login wall: nessun header di sicurezza
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            q = (parse_qs(p.query).get("q") or [""])[0]
            if self.path.startswith("/axss-vuln"):
                page = f"<html><body><p>Area riservata. Hai cercato: {q}</p></body></html>"           # RAW → XSS
            else:
                page = f"<html><body><p>Area riservata. Hai cercato: {html.escape(q)}</p></body></html>"  # escapato
            body = page.encode()
            self.send_response(200)
            # Header di sicurezza presente SOLO sulla pagina autenticata: è il
            # segnale osservabile che prova che `check` ha instradato la sessione
            # (il login wall non lo porta). X-Frame-Options non collide con lo
            # header Server auto-iniettato da BaseHTTPRequestHandler.
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        q = (parse_qs(p.query).get("q") or [""])[0]
        if self.path.startswith("/xss-vuln"):
            page = f"<html><body><p>Hai cercato: {q}</p></body></html>"          # RAW → XSS
        elif self.path.startswith("/xss-safe"):
            page = f"<html><body><p>Hai cercato: {html.escape(q)}</p></body></html>"  # escapato
        else:
            return self._reply(404, {"error": "not found"})
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Risposta al preflight CORS. La debolezza preflight-only vive qui:
        riflette l'origine nella risposta all'OPTIONS, non nella GET semplice."""
        origin = self.headers.get("Origin", "")
        acrm = self.headers.get("Access-Control-Request-Method", "") or "GET, POST, PUT, DELETE"
        acrh = self.headers.get("Access-Control-Request-Headers", "") or "*"
        if self.path.startswith("/cors-preflight-vuln"):
            self.send_response(204)
            # VULNERABILE: il preflight riflette QUALSIASI origine + credenziali
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Access-Control-Allow-Methods", acrm)
                self.send_header("Access-Control-Allow-Headers", acrh)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/cors-preflight-safe"):
            self.send_response(204)
            # SICURO: il preflight riflette solo l'origine in allowlist
            if origin == _CORS_TRUSTED:
                self.send_header("Access-Control-Allow-Origin", _CORS_TRUSTED)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Access-Control-Allow-Methods", "GET, POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # altri path: nessun CORS nel preflight (così /cors-safe resta pulito)
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        # --- BANCO AVVERSARIALE: le trappole rispondono anche in POST (vedi do_GET) --
        if self.path == "/trap-echo":
            # ECO VERBATIM del corpo grezzo (SQLi json, mass-assign json): entrambi i
            # campi riemergono identici → nessun differenziale / eco indiscriminato.
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            self._trap_text("ECHO: " + raw.decode("utf-8", "replace"))
            return
        if self.path.startswith("/trap-spa"):
            self._trap_spa()                         # 200 costante (NoSQLi/CSRF/stored-xss)
            return
        if self.path.startswith("/trap-latency"):
            time.sleep(random.uniform(0, 0.12))
            self._trap_text("ok")
            return
        if self.path.startswith("/xxe-vuln") or self.path.startswith("/xxe-safe"):
            # XXE: un'API che PARSA il corpo XML e rende il testo parsato.
            #   VULN → parser con external entities ABILITATE: un'entità SYSTEM
            #          'file://' è risolta → il contenuto del file (/etc/passwd)
            #          entra nel testo reso → arbitrary file read.
            #   SAFE → external-entity processing DISABILITATO (la difesa canonica)
            #          → l'entità non è espansa → nessun contenuto di file.
            vuln = self.path.startswith("/xxe-vuln")
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                parsed = _xxe_parse(raw.decode("utf-8", "replace"), resolve_external=vuln)
            except Exception:
                parsed = ""                          # XML malformato → nessun testo
            body = ("<result>" + parsed + "</result>").encode("utf-8", "replace")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/graphql-vuln" or self.path == "/graphql-safe":
            vuln = self.path.endswith("-vuln")
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("application/x-www-form-urlencoded"):
                # Transport FORM-urlencoded (CORS-"semplice" → vettore CSRF). Due
                # facce SOLO sulla CSRF da mutation via form POST:
                #   - VULN → esegue l'operazione dal campo form `query`, MUTATION
                #     comprese → nessun token, content-type semplice = forgeable
                #     cross-site (un `<form>` ad auto-submit basta);
                #   - SAFE → esige `application/json` per le mutation (415 sul form),
                #     così il preflight CORS scatta → non forgeable via form semplice
                #     (best practice OWASP).
                n = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(n) if n else b""
                q = (parse_qs(raw.decode("utf-8", "replace")).get("query") or [""])[0]
                is_mut = q.lstrip().startswith("mutation")
                if not vuln and is_mut:
                    return self._reply(415, {"errors": [{"message":
                        "Mutations must be sent as application/json."}]})
                root = "Mutation" if is_mut else "Query"
                return self._reply(200, {"data": {"__typename": root}})
            # Endpoint GraphQL (POST JSON). Il corpo può essere un dict (query
            # singola) o una LISTA (batch): lo leggo qui perché self._body()
            # consumerebbe rfile e il generico `d` più sotto assume un dict.
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                body = {}
            code, obj = _graphql_handle(body, vuln=vuln)
            return self._reply(code, obj)
        if self.path == "/csrf-vuln" or self.path == "/csrf-safe":
            # Endpoint che CAMBIA STATO, autenticato dal cookie di sessione.
            # Leggo i campi PRIMA di self._body() (che consumerebbe il corpo).
            cookie = self.headers.get("Cookie", "")
            fields = self._fields()
            token = str(fields.get("csrf_token", ""))
            if "sess_valid_123" not in cookie:
                # Guardia: senza sessione nessuno dei due esegue (il cookie CONTA).
                return self._reply(401, {"error": "no session"})
            if self.path == "/csrf-safe" and token != CSRF_TOKEN:
                # SICURO: il token anti-CSRF è VALIDATO (errato/assente → rifiutato).
                return self._reply(403, {"error": "csrf token invalido"})
            # /csrf-vuln: il token è IGNORATO, basta il cookie → forgeable cross-site.
            return self._reply(200, {"ok": True, "changed": True})
        if self.path == "/profile-vuln" or self.path == "/profile-safe":
            # mass-assignment: la SCRITTURA aggiorna il profilo e risponde con lo stato.
            # Leggo i campi PRIMA di self._body() (che consumerebbe il corpo).
            store = "vuln" if self.path.endswith("-vuln") else "safe"
            fields = self._fields()
            if store == "vuln":
                # VULNERABILE: lega ogni campo del corpo che è una "colonna" del
                # modello (un campo-esca ignoto viene scartato), COMPRESO `role`
                # → il client può elevarsi il ruolo = mass assignment.
                for k, v in fields.items():
                    if k in _MA_COLUMNS:
                        _PROFILE["vuln"][k] = v
            else:
                # SICURO: solo i campi esplicitamente client-settable (whitelist);
                # `role` e qualunque esca restano fuori.
                for k, v in fields.items():
                    if k in _MA_SETTABLE:
                        _PROFILE["safe"][k] = v
            return self._reply(200, _PROFILE[store])
        if self.path == "/asqli-vuln" or self.path == "/asqli-safe":
            # SQL injection DIETRO L'AUTENTICAZIONE (superficie loggata): modella
            # una ricerca riservata che costruisce la query SQL. Senza sessione
            # valida → 401 login wall con corpo COSTANTE (nessuna query valutata):
            # baseline/apice/true/false tornano identici → la lane sqli TACE (no
            # FP). Con la sessione instradata in core.probe → l'endpoint esegue la
            # query (vuln: input concatenato → iniettabile; safe: valori legati).
            # Prova che `--cookie`/`--token`/`--header` raggiungono la SQLi loggata.
            if not _authed(self.headers):
                return self._reply(401, {"error": "login required"})
            d = self._body()
            u, p = str(d.get("username", "")), str(d.get("password", ""))
            with _LOCK:
                try:
                    if self.path == "/asqli-vuln":
                        q = f"SELECT id FROM users WHERE username='{u}' AND password='{p}'"
                        row = _DB.execute(q).fetchone()
                    else:
                        row = _DB.execute(
                            "SELECT id FROM users WHERE username=? AND password=?", (u, p)
                        ).fetchone()
                except Exception as e:
                    return self._reply(500, {"error": f"SQL error: {e}"})
            return self._reply(200, {"ok": True, "token": "demo"}) if row \
                else self._reply(401, {"ok": False})
        if self.path == "/nosqli-br-vuln" or self.path == "/nosqli-br-safe":
            # NoSQLi in BRACKET-NOTATION (form-urlencoded, stile Express
            # qs/body-parser 'extended' / PHP): una chiave `campo[$op]=val` nel
            # form. Legge il corpo grezzo (NON JSON) prima del _body() generico.
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            if self.path == "/nosqli-br-vuln":
                # VULNERABILE: ricostruisce i dict annidati → gli operatori Mongo
                # passati in bracket-notation RAGGIUNGONO la query e sono VALUTATI.
                f = _parse_bracket(raw)
                ok = _mongo_match(f.get("username", ""), "admin") and \
                    _mongo_match(f.get("password", ""), "secret")
            else:
                # SICURO: NON ricostruisce i bracket → la chiave `username[$ne]`
                # resta piatta, `username` è assente → mai un operatore valutato
                # (solo stringhe, confronto di sola uguaglianza).
                f = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
                ok = (str(f.get("username", "")) == "admin" and str(f.get("password", "")) == "secret")
            return self._reply(200, {"ok": True, "token": "demo"}) if ok \
                else self._reply(401, {"ok": False})
        d = self._body()
        if self.path == "/nosqli-vuln" or self.path == "/nosqli-safe":
            # "db": utente admin / password 'secret'. I valori grezzi (non
            # stringhizzati) contano: un operatore nel body resta un dict.
            uin, pin = d.get("username", ""), d.get("password", "")
            if self.path == "/nosqli-vuln":
                # VULNERABILE: gli operatori Mongo nel body vengono VALUTATI
                ok = _mongo_match(uin, "admin") and _mongo_match(pin, "secret")
            else:
                # SICURO: username/password coerciti a stringa → sola uguaglianza
                ok = (str(uin) == "admin" and str(pin) == "secret")
            return self._reply(200, {"ok": True, "token": "demo"}) if ok \
                else self._reply(401, {"ok": False})
        if self.path == "/comment-vuln" or self.path == "/comment-safe":
            # stored-XSS: persiste il commento (grezzo) nella bacheca; la resa
            # cruda-vs-escapata avviene in LETTURA (do_GET /comments-*).
            store = "vuln" if self.path.endswith("-vuln") else "safe"
            _COMMENTS[store].append(str(d.get("comment", "")))
            return self._reply(200, {"ok": True, "stored": True})
        if self.path == "/acomment-vuln" or self.path == "/acomment-safe":
            # stored-XSS DIETRO AUTH (SCRITTURA sulla bacheca riservata). Senza
            # sessione valida → 401 login wall, NIENTE persistenza: il canary non
            # entra, quindi in lettura non riemerge → la lane TACE (no FP). Con la
            # sessione instradata in core.probe → il commento è persistito (grezzo);
            # la resa cruda-vs-escapata avviene in LETTURA (do_GET /acomments-*).
            if not _authed(self.headers):
                return self._reply(401, {"error": "login required"})
            store = "vuln" if self.path.endswith("-vuln") else "safe"
            _ACOMMENTS[store].append(str(d.get("comment", "")))
            return self._reply(200, {"ok": True, "stored": True})
        if self.path == "/trap-auth-lockout":
            # TRAPPOLA AUTH (banco avversariale): login SANO ma ingannevole. NON
            # usa il 429 canonico — fa LOCKOUT per TRANSIZIONE di status: 401 ai
            # primi tentativi, poi 403 (IP/account bloccato) e ci RESTA. A uno
            # scanner ingenuo (che cerca solo 429/423) sembra "nessun throttling"
            # → falso positivo; la lane robusta riconosce la transizione tardiva e
            # persistente verso uno status bloccante (`_lockout_transition`) → TACE.
            # Contatore dedicato monotòno, chiamata SINGOLA nel banco (come
            # /auth-ratelimited): 401 ai primi 3 tentativi, 403 dai successivi.
            with _LOCK:
                _LOCKOUT["n"] += 1
                n = _LOCKOUT["n"]
            return self._reply(403, {"error": "locked"}) if n > 3 \
                else self._reply(401, {"ok": False})
        u, p = str(d.get("username", "")), str(d.get("password", ""))
        if self.path == "/auth-norate":          # login SENZA throttling: sempre 401
            return self._reply(401, {"ok": False})
        if self.path == "/auth-ratelimited":     # login CON throttling: 429 dopo 5 tentativi
            with _LOCK:
                _RL["n"] += 1
                n = _RL["n"]
            return self._reply(429, {"error": "too many requests"}) if n > 5 \
                else self._reply(401, {"ok": False})
        if self.path == "/race-vuln":            # check-then-set NON atomico + finestra → TOCTOU
            if _RACE["vuln"]:
                return self._reply(409, {"error": "already"})
            time.sleep(0.05)
            _RACE["vuln"] = True
            return self._reply(200, {"redeemed": True})
        if self.path == "/race-safe":            # sezione critica sotto lock → serializzata
            with _LOCK:
                if _RACE["safe"]:
                    return self._reply(409, {"error": "already"})
                _RACE["safe"] = True
            return self._reply(200, {"redeemed": True})
        with _LOCK:
            try:
                if self.path == "/login-vuln":
                    # VULNERABILE: input concatenato nella stringa SQL
                    q = f"SELECT id FROM users WHERE username='{u}' AND password='{p}'"
                    row = _DB.execute(q).fetchone()
                elif self.path == "/login-safe":
                    # SICURO: valori legati come parametri, mai come codice
                    row = _DB.execute(
                        "SELECT id FROM users WHERE username=? AND password=?", (u, p)
                    ).fetchone()
                else:
                    return self._reply(404, {"error": "not found"})
            except Exception as e:
                # l'errore SQL finisce nel corpo → superficie per l'error-based
                return self._reply(500, {"error": f"SQL error: {e}"})
        self._reply(200, {"ok": True, "token": "demo"}) if row else self._reply(401, {"ok": False})


# --- Fixture TLS per la lane `tls` ------------------------------------------
# La lane `tls` ispeziona il certificato all'handshake, non fa HTTP: basta un
# server TLS minimale che completa l'handshake col cert dato (scaduto o valido),
# poi chiude. I certificati sono PEM STATICI committati in `bench_certs/`
# (generati una tantum con openssl, firmati dalla CA `ca-bundle.crt`): il
# runtime usa solo lo stdlib `ssl`, nessuna dipendenza.
import ssl as _ssl
import socket as _socket

_CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_certs")


def _serve_tls(port, certfile, keyfile):
    """Server TLS minimale su 127.0.0.1:port che serve `certfile` (scaduto o
    valido). load_cert_chain NON controlla la validità: il cert scaduto viene
    servito e sarà il CLIENT (la lane, con verifica piena) a rifiutarlo → è
    esattamente lo scenario reale che vogliamo misurare."""
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def _handle(conn):
        try:
            s = ctx.wrap_socket(conn, server_side=True)
            try:
                s.recv(32)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        except Exception:
            # Il client che verifica aborta l'handshake su cert scaduto → reset
            # lato server: atteso, non è un errore del fixture.
            try:
                conn.close()
            except Exception:
                pass

    def _loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_loop, daemon=True).start()
    return srv


def serve(host="127.0.0.1", port=8099):
    srv = ThreadingHTTPServer((host, port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # Server TLS per la lane `tls`: vuln = cert SCADUTO (8100), safe = cert VALIDO
    # (8101). Entrambi col SAN 127.0.0.1/localhost, firmati dalla stessa CA
    # (bench_certs/ca-bundle.crt) → l'UNICA differenza di verifica è la scadenza.
    _serve_tls(8100, os.path.join(_CERTS, "expired.crt"), os.path.join(_CERTS, "expired.key"))
    _serve_tls(8101, os.path.join(_CERTS, "valid.crt"), os.path.join(_CERTS, "valid.key"))
    return srv


if __name__ == "__main__":
    serve()
    print("fixture vulnerabile su http://127.0.0.1:8099  (/login-vuln · /login-safe)")
    while True:
        time.sleep(1)
