"""Lane OPENAPI — ingestione di uno spec OpenAPI/Swagger.

Invece di *indovinare* gli endpoint (come fa `discover` con ffuf), qui li
LEGGIAMO dallo spec dichiarato dal servizio: ogni operazione (metodo + path +
parametri) è un fatto scritto nel contratto. Poi, su ogni endpoint applicabile,
giriamo le lane attive deterministiche che non hanno bisogno di materiale
esterno — `check` (sulla base), `xss` (reflected), `sqli` (login-like) e `auth`
(resistenza al brute-force dei login-like).

Perché funziona: lo spec dice NOME, POSIZIONE e TIPO di ogni parametro. Da lì
il dispatch è meccanico:
  - ogni parametro STRINGA in query/body/form → candidato per reflected XSS;
  - un'operazione POST/PUT con un campo credenziale (username/user/email/login)
    → candidato per SQLi sul login (iniettiamo quel campo, gli altri benigni);
  - un'operazione POST/PUT con un campo credenziale E un campo password →
    è un LOGIN dichiarato dal contratto → candidato per `auth` (brute-force):
    non serve indovinare dove sta il login, lo dice lo spec.

Determinismo: i fatti li fanno le lane sottostanti (stessa evidenza, stesso
PoC). Questa lane si limita a ENUMERARE dallo spec e a comporre — non inventa
nulla. Puro Python: JSON con stdlib, YAML solo se `pyyaml` è presente.

Confine: come ogni lane, le richieste passano da core.probe → solo ALLOWLIST.

Dispatch e limiti onesti per lane:
  - `idor` richiede un'IDENTITÀ (token/header) che lo spec dichiara come REQUISITO
    (securitySchemes) ma di cui NON porta il valore. Perciò `idor` è nel dispatch
    MA non nel default: si attiva solo se chiami `openapi --lanes ...,idor` E passi
    un'identità (`--token`, oppure `--id-header`+`--identity`). Senza identità la
    lane non viene eseguita e lo diciamo (finding info). Il bersaglio è ogni
    operazione GET con un parametro id-like nel PATH (es. `/basket/{id}`): quel
    placeholder diventa il punto in cui `idor` sostituisce la risorsa TUA e quella
    ALTRUI, gli altri placeholder sono concretizzati a un valore campione.
  - `auth` NON ha bisogno di credenziali reali (usa uno username FINTO e misura il
    throttling), quindi è interamente guidabile dal contratto → è nel dispatch.
  - `nosqli` (operator-injection sul login) ha lo STESSO trigger di `auth` — un
    corpo con campo identità E campo password = un login dal contratto — e usa uno
    username finto (operatore sempre-vero), quindi non tocca account reali. È nel
    dispatch ma NON nel default: si attiva solo con `--lanes …,nosqli`, per non
    cambiare l'output di `openapi` senza che sia richiesto. Il transport (body JSON
    o bracket-notation form) lo dice il content-type dichiarato nello spec.
  - `ssti` (Server-Side Template Injection) ha lo STESSO bersaglio di `xss` — ogni
    parametro STRINGA riflesso in query/body/form — ma prova la VALUTAZIONE lato
    server di un'espressione di template, non solo la riflessione (metodo
    differenziale: marker+prodotto calcolato = valutato; marker+payload letterale =
    riflesso ma non valutato → tace). È interamente guidabile dal contratto (nessuna
    credenziale) ma, come `nosqli`, NON è nel default: va chiesta con `--lanes …,ssti`
    per non cambiare l'output di `openapi` senza che sia richiesto.
  - `traversal` (Path Traversal / LFI) mira ogni parametro STRINGA che porta un
    NOME DI FILE / PATH (`file`/`page`/`path`/`template`/…), non ogni parametro
    stringa: come `idor` sceglie i soli id-like nel path, `traversal` sceglie i soli
    file-param (un `username`/`q` non è un file-read). La firma è OGGETTIVA (il
    contenuto di un file di sistema noto), quindi un parametro riflesso crudo non la
    produce. Interamente guidabile dal contratto (nessuna credenziale) ma, come
    `nosqli`/`ssti`, NON è nel default: va chiesta con `--lanes …,traversal`.
  - `redirect` (open redirect) mira ogni parametro STRINGA di QUERY su una GET che
    porta una DESTINAZIONE DI REDIRECT (`to`/`url`/`next`/`redirect`/`return`/…),
    non ogni parametro stringa: come `traversal` sceglie i soli file-param e `idor`
    i soli id-like, `redirect` sceglie i soli parametri redirect-like (un `q`/
    `username` non reindirizza). La firma è OGGETTIVA (un 3xx con Location verso il
    canary ESTERNO, mai contattato), quindi un parametro riflesso crudo non la
    produce. Interamente guidabile dal contratto (nessuna credenziale) ma, come
    `nosqli`/`ssti`/`traversal`, NON è nel default: va chiesta con `--lanes …,redirect`.
  - `ssrf` mira ogni parametro STRINGA che porta una URL che il server andrà a
    RICHIEDERE (`url`/`uri`/`webhook`/`callback`/`src`/`image`/…), non ogni parametro
    stringa: come `redirect`/`traversal`/`idor`, un dispatch SELETTIVO per nome (un
    `q`/`username`/`page` non innesca un fetch server-side). La prova è OGGETTIVA e
    out-of-band (il canary locale colpito col nonce, non la riflessione), quindi un
    parametro riflesso crudo non la produce. Il transport lo dice la posizione (query
    = fetcher GET, body/form = webhook POST). Interamente guidabile dal contratto
    (nessuna credenziale) ma, come `nosqli`/`ssti`/`traversal`/`redirect`, NON è nel
    default: va chiesta con `--lanes …,ssrf`. Con questa, TUTTE le lane a parametro
    sono dispatchabili dal contratto.
  - `crlf` (CRLF / response-header injection) mira i soli parametri HEADER-SINK
    (redirect-like ∪ url-like) in GET; prova STRUTTURALE (l'header-sentinella
    riemerge come header di risposta). Opt-in come sopra: `--lanes …,crlf`.
  - `jwt` (debolezze della verifica dei token) mira le sole GET che lo spec
    dichiara protette da uno schema BEARER (`securitySchemes: type=http,
    scheme=bearer`): è lì che un `Authorization: Bearer` è accettato. Come `idor`,
    lo spec dice DOVE il token è accettato ma NON ne porta il VALORE (il token
    legittimo arriva via `--token`); senza il token la lane non viene eseguita e lo
    diciamo (finding info). Solo GET (lettura, nessun effetto collaterale). È nel
    dispatch ma NON nel default: va chiesta con `--lanes …,jwt` + `--token`.
  - risoluzione `$ref` solo locale (`#/...`); niente spec remoti/federati. La
    COMPOSIZIONE dello schema di un corpo è risolta (`allOf` merge, `oneOf`/`anyOf`
    union, `$ref` annidati) → un corpo composto non perde i suoi campi iniettabili.
"""

import json
import os

from core import finding
import lane_check
import lane_xss
import lane_attack
import lane_auth
import lane_idor
import lane_nosqli
import lane_ssti
import lane_traversal
import lane_redirect
import lane_ssrf
import lane_crlf
import lane_jwt

# Campi "identità" di un login (non la password): su questi proviamo la SQLi.
CRED_FIELDS = {"username", "user", "email", "login", "mail", "userid", "user_name"}

# Campi "password" di un login: la loro presenza (insieme a un campo identità)
# marca un'operazione come LOGIN → candidato per il test di brute-force `auth`.
PASS_FIELDS = {"password", "pass", "passwd", "pwd", "passphrase", "secret"}

# Nomi di parametro di PATH che denotano un IDENTIFICATORE di risorsa: su questi,
# in GET, proviamo l'IDOR (cambiare l'id per leggere la risorsa di un altro).
# L'insieme copre le forme tutte-minuscole più comuni; le regole di suffisso sotto
# (`_id`, camelCase `...Id`/`...ID`) coprono il resto senza abboccare a nomi come
# "valid"/"grid"/"paid" (che finiscono in "id" ma non sono identificatori).
_ID_PATH_NAMES = {"id", "uid", "uuid", "guid", "pid", "oid", "sid",
                  "userid", "user_id", "orderid", "order_id",
                  "basketid", "basket_id", "productid", "product_id",
                  "itemid", "item_id", "accountid", "account_id", "docid", "doc_id"}

# Nomi di parametro STRINGA che denotano un NOME DI FILE / PATH: su questi
# proviamo il path traversal / LFI. Come `idor` mira i soli id-like nel path e
# `auth`/`sqli`/`nosqli` i soli campi credenziale, `traversal` mira i soli
# parametri che portano un riferimento a file — un `username`/`q` non è un
# file-read. L'insieme copre i nomi più comuni; la regola di sottostringa sotto
# (`file`/`path` dentro il nome) copre filepath/logfile/pathname/download_path.
_FILE_PARAM_NAMES = {"file", "filename", "filepath", "path", "pathname",
                     "page", "doc", "document", "template", "tpl", "download",
                     "dir", "directory", "folder", "include", "resource",
                     "load", "view", "attachment", "src", "source"}

# Nomi di parametro di QUERY che denotano una DESTINAZIONE DI REDIRECT: su questi,
# in GET, proviamo l'open redirect (il valore controlla dove l'app manda l'utente).
# Come `idor` mira i soli id-like nel path e `traversal` i soli file-param,
# `redirect` mira i soli parametri redirect-like — un `q`/`username` non reindirizza.
# L'insieme copre i nomi più comuni (login `next`/`returnUrl`, OAuth `redirect_uri`);
# la regola di sottostringa sotto (`redirect`/`return` nel nome) copre le varianti.
_REDIRECT_PARAM_NAMES = {"to", "url", "uri", "next", "redirect", "redir",
                         "redirect_uri", "redirect_url", "return", "returnurl",
                         "return_url", "returnto", "return_to", "dest",
                         "destination", "continue", "goto", "forward",
                         "callback", "link", "rurl"}

# Nomi di parametro STRINGA che denotano una URL/destinazione che il server
# andrà a RICHIEDERE (fetcher di immagini, webhook, importatore, anteprima link):
# su questi proviamo l'SSRF (il server segue un URL scelto dal client). Come
# `idor` mira i soli id-like, `traversal` i soli file-param e `redirect` i soli
# redirect-like, `ssrf` mira i soli parametri URL-like — un `q`/`username`/`page`
# non innesca un fetch server-side. L'insieme copre i nomi più comuni; la regola
# di sottostringa sotto (`url`/`webhook`/`callback` nel nome) copre imageUrl/
# webhook_url/callbackUrl. Nota: `uri` NON è una sottostringa valida (abboccherebbe
# a "security"/"maturity"), solo un nome esatto.
_URL_PARAM_NAMES = {"url", "uri", "link", "href", "callback", "webhook",
                    "fetch", "target", "dest", "destination", "feed",
                    "endpoint", "proxy", "remote", "site", "domain", "host",
                    "image", "avatar", "upstream", "src", "source"}

# Metodi su cui ha senso un body iniettabile (login-like).
_WRITE_METHODS = {"post", "put", "patch"}

# Lane disponibili al dispatch automatico (quelle senza materiale esterno:
# `auth` compreso, perché usa uno username finto e non richiede credenziali reali).
# `idor` NON è nel default: richiede un'identità che lo spec non porta (vedi docstring).
DEFAULT_LANES = ("check", "xss", "sqli", "auth")


# --- parsing dello spec -----------------------------------------------------
def load_spec(path):
    """Legge uno spec da file: prima JSON (stdlib), poi YAML se `pyyaml` c'è.
    Ritorna (dict, None) o (None, messaggio_errore)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as e:
        return None, f"impossibile leggere lo spec: {e}"
    try:
        return json.loads(raw), None
    except ValueError:
        pass
    try:
        import yaml                                  # opzionale
        obj = yaml.safe_load(raw)
        if isinstance(obj, dict):
            return obj, None
        return None, "lo spec YAML non è un oggetto"
    except ImportError:
        return None, "spec non-JSON e 'pyyaml' assente: installa pyyaml o usa JSON"
    except Exception as e:                           # YAML malformato
        return None, f"spec YAML non valido: {e}"


def _deref(node, root, _depth=0):
    """Risolve un `$ref` locale (`#/a/b/c`). Solo riferimenti interni, con un
    limite di profondità per non andare in loop."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return node                               # ref esterno: non lo seguiamo
        cur = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")   # JSON-Pointer
            if not isinstance(cur, dict) or part not in cur:
                return node                           # ref rotto: lasciamo com'è
            cur = cur[part]
        node, seen = cur, seen + 1
    return node


def base_url(spec, override=None):
    """Ricava la base URL: override > servers (v3) > schemes+host+basePath (v2)."""
    if override:
        return override.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "")
        if u:
            return u.rstrip("/")
    host = spec.get("host")                           # Swagger v2
    if host:
        scheme = (spec.get("schemes") or ["http"])[0]
        return f"{scheme}://{host}{spec.get('basePath', '')}".rstrip("/")
    return None


def _schema_type(schema, root):
    schema = _deref(schema or {}, root)
    t = schema.get("type")
    return t if isinstance(t, str) else None


def _schema_properties(schema, root, _depth=0):
    """Estrae {nome: schema} delle proprietà di uno schema oggetto, risolvendo la
    COMPOSIZIONE JSON-Schema che gli spec reali usano di continuo:

      - `allOf` — il corpo è l'unione di più frammenti (tipicamente `$ref` a un
        modello base + proprietà locali): fondiamo i campi di tutti i membri;
      - `oneOf`/`anyOf` — varianti alternative: ne prendiamo l'UNIONE, perché ai
        fini del dispatch ogni campo che *può* comparire è un candidato iniettabile
        (onesto: proviamo tutta la superficie possibile, non una sola variante);
      - `$ref` locali annidati (anche dentro i membri `allOf`/`oneOf`), via `_deref`.

    Senza questo, un corpo composto via `allOf`/`$ref` esporrebbe ZERO proprietà
    (`sch.get("properties")` è vuoto sul contenitore) → il dispatch xss/sqli/auth
    salterebbe l'endpoint e la superficie dichiarata dal contratto andrebbe persa.
    Deterministico, puro parsing; il limite di profondità evita i cicli di `$ref`."""
    if _depth > 8 or not isinstance(schema, dict):
        return {}
    schema = _deref(schema, root)
    if not isinstance(schema, dict):
        return {}
    props = {}
    # composizione: raccogli prima i campi dei membri (allOf merge / oneOf-anyOf union)
    for key in ("allOf", "oneOf", "anyOf"):
        members = schema.get(key)
        if isinstance(members, list):
            for m in members:
                for pname, psch in _schema_properties(m, root, _depth + 1).items():
                    props.setdefault(pname, psch)          # il primo che definisce il campo vince
    # proprietà dirette del nodo: hanno la precedenza (override locale sul modello base)
    direct = schema.get("properties")
    if isinstance(direct, dict):
        for pname, psch in direct.items():
            props[pname] = psch
    return props


def _params_of(op, path_item, root):
    """Normalizza i parametri di un'operazione in una lista di dict
    {name, loc, type}, con loc ∈ {query, path, header, body, form}.
    Unisce i parametri a livello di path con quelli dell'operazione e legge il
    requestBody (v3) / i parametri `in: body`/`formData` (v2)."""
    out = []
    raw = list(path_item.get("parameters") or []) + list(op.get("parameters") or [])
    for p in raw:
        p = _deref(p, root)
        if not isinstance(p, dict):
            continue
        loc = p.get("in")
        name = p.get("name")
        if not name or loc not in ("query", "path", "header"):
            # v2 body/formData li trattiamo sotto; header raramente iniettabile
            if loc == "formData" and name:
                out.append({"name": name, "loc": "form", "type": p.get("type")})
            elif loc == "body":                       # v2: schema con properties
                sch = _deref(p.get("schema") or {}, root)
                for pname, psch in _schema_properties(sch, root).items():
                    out.append({"name": pname, "loc": "body",
                                "type": _schema_type(psch, root)})
            continue
        t = p.get("type") or _schema_type(p.get("schema"), root)   # v2 inline / v3 schema
        out.append({"name": name, "loc": loc, "type": t})

    body = _deref(op.get("requestBody") or {}, root)  # v3 requestBody
    content = body.get("content") or {}
    for ctype in ("application/json", "application/x-www-form-urlencoded"):
        media = content.get(ctype)
        if not isinstance(media, dict):
            continue
        sch = _deref(media.get("schema") or {}, root)
        loc = "body" if ctype == "application/json" else "form"
        for pname, psch in _schema_properties(sch, root).items():
            out.append({"name": pname, "loc": loc, "type": _schema_type(psch, root)})
        break                                         # un solo content-type ci basta
    return out


def operations(spec):
    """Genera le operazioni dichiarate: dict {method, path, params}."""
    root = spec
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        item = _deref(item, root)
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            # `security` EFFETTIVA: quella dell'operazione se dichiarata (anche `[]`,
            # che significa "pubblica" e sovrascrive il globale), altrimenti quella
            # globale dello spec. Serve a `jwt` per sapere QUALI endpoint accettano
            # un Bearer (lo spec dice DOVE, il flag `--token` porta il valore).
            sec = op["security"] if "security" in op else spec.get("security")
            ops.append({"method": method.upper(), "path": path,
                        "params": _params_of(op, item, root), "security": sec})
    return ops


# --- dispatch verso le lane -------------------------------------------------
def _concrete_path(path):
    """Sostituisce i placeholder `{x}` del path con un valore campione (1)."""
    out, buf, indeps = [], "", False
    for ch in path:
        if ch == "{":
            indeps = True
            buf = ""
        elif ch == "}":
            indeps = False
            out.append("1")                           # valore campione
        elif indeps:
            buf += ch
        else:
            out.append(ch)
    return "".join(out)


def _send_as(loc):
    return {"query": "query", "body": "json", "form": "form"}.get(loc, "query")


def _is_id_path_param(name):
    """Un parametro di PATH è un identificatore di risorsa (candidato IDOR)?
    Deterministico, dal solo nome: nomi noti (`id`, `userId`, …), suffisso `_id`/
    `-id`, o camelCase/PascalCase `...Id`/`...ID`. Esclude di proposito "valid",
    "grid", "paid", "void" (finiscono in "id" minuscolo ma non sono id)."""
    n = (name or "").strip()
    low = n.lower()
    if low in _ID_PATH_NAMES:
        return True
    if low.endswith("_id") or low.endswith("-id"):
        return True
    # camelCase/PascalCase: ...Id / ...ID, ma solo se la lettera prima è minuscola
    # (userId → sì; basketID → sì; "ID" tutto maiuscolo o "valid" → no).
    if len(n) >= 3 and n[-2:] in ("Id", "ID") and n[-3].islower():
        return True
    return False


def _bearer_schemes(spec):
    """Nomi degli schemi di sicurezza BEARER dichiarati dallo spec (OpenAPI 3:
    `type: http, scheme: bearer`, con o senza `bearerFormat: JWT`). Gli endpoint
    che li richiedono accettano un token via `Authorization: Bearer` → è lì che
    `jwt` prova le debolezze di verifica. Deterministico, dal solo contratto."""
    comp = spec.get("components")
    schemes = (comp.get("securitySchemes") if isinstance(comp, dict) else None) or {}
    names = set()
    for name, s in schemes.items():
        if (isinstance(s, dict)
                and str(s.get("type", "")).lower() == "http"
                and str(s.get("scheme", "")).lower() == "bearer"):
            names.add(name)
    return names


def _requires_bearer(security, bearer_names):
    """L'operazione richiede un Bearer? Vero se UNA delle alternative in `security`
    (OR fra i requisiti) cita uno schema bearer. `security` assente o `[]`
    (endpoint pubblico) → falso. Lo spec dice DOVE il Bearer è accettato; il valore
    del token NON è nel contratto (arriva via `--token`), come per `idor`."""
    if not security or not bearer_names:
        return False
    for req in security:
        if isinstance(req, dict) and any(k in bearer_names for k in req):
            return True
    return False


def _is_file_param(name):
    """Un parametro STRINGA porta un NOME DI FILE / PATH (candidato traversal)?
    Deterministico, dal solo nome dichiarato dallo spec: un nome noto (`file`,
    `page`, `path`, `template`, `download`, …) o un nome che CONTIENE "file"/"path"
    (filepath, logfile, pathname, download_path). Un parametro come `username`/`q`
    non è un file-read → escluso, così il traversal è provato solo dove ha senso
    (come `idor` mira i soli id-like, non ogni parametro di path)."""
    n = (name or "").strip().lower().replace("-", "_")
    if n in _FILE_PARAM_NAMES:
        return True
    if "file" in n or "path" in n:
        return True
    return False


def _is_redirect_param(name):
    """Un parametro STRINGA di query porta una DESTINAZIONE DI REDIRECT (candidato
    open-redirect)? Deterministico, dal solo nome dichiarato dallo spec: un nome
    noto (`to`, `url`, `next`, `redirect`, `return`, …) o un nome che CONTIENE
    "redirect"/"return" (redirect_uri, returnUrl, redirectTo). Un parametro come
    `q`/`username` non reindirizza → escluso, così l'open-redirect è provato solo
    dove ha senso (come `idor` mira i soli id-like, `traversal` i soli file-param)."""
    n = (name or "").strip().lower().replace("-", "_")
    if n in _REDIRECT_PARAM_NAMES:
        return True
    if "redirect" in n or "return" in n:
        return True
    return False


def _is_url_param(name):
    """Un parametro STRINGA porta una URL che il server andrà a RICHIEDERE
    (candidato SSRF)? Deterministico, dal solo nome dichiarato dallo spec: un nome
    noto (`url`, `uri`, `webhook`, `callback`, `src`, `image`, …) o un nome che
    CONTIENE "url"/"webhook"/"callback" (imageUrl, webhook_url, callbackUrl). Un
    parametro come `q`/`username`/`page` non innesca un fetch server-side → escluso,
    così l'SSRF è provato solo dove ha senso (come `idor` mira i soli id-like,
    `traversal` i soli file-param, `redirect` i soli redirect-like). `uri` resta un
    nome ESATTO, non una sottostringa (eviterebbe falsi amici come "security")."""
    n = (name or "").strip().lower().replace("-", "_")
    if n in _URL_PARAM_NAMES:
        return True
    if "url" in n or "webhook" in n or "callback" in n:
        return True
    return False


def _is_header_sink_param(name):
    """Un parametro STRINGA di query porta un valore che il server può scrivere in
    un HEADER di risposta (candidato CRLF / response-header injection)? Il sink
    canonico è il `Location` di un redirect (parametro redirect-like), ma anche gli
    header costruiti da una URL (`Link`, `Set-Cookie` derivato) → l'insieme è
    l'UNIONE di redirect-like e url-like: come `redirect` sceglie i redirect-like e
    `ssrf` gli url-like, `crlf` mira i soli parametri il cui valore finisce
    plausibilmente in un header — un `q`/`username` non ci finisce. La prova resta
    STRUTTURALE (l'header-sentinella iniettato riemerge come header di risposta),
    quindi lo spray sui soli header-sink non introduce falsi positivi."""
    return _is_redirect_param(name) or _is_url_param(name)


def _idor_url(path, keep_name):
    """Path per la lane `idor`: il placeholder id-like diventa il sentinel `{id}`
    (che `idor` sostituisce con la risorsa TUA e quella ALTRUI); ogni altro
    placeholder è concretizzato a un valore campione (1)."""
    out, buf, inside = [], "", False
    for ch in path:
        if ch == "{":
            inside, buf = True, ""
        elif ch == "}":
            inside = False
            out.append("{id}" if buf == keep_name else "1")   # sentinel per idor vs campione
        elif inside:
            buf += ch
        else:
            out.append(ch)
    return "".join(out)


def scan_spec(path, base=None, lanes=DEFAULT_LANES,
              token=None, id_header=None, identity=None, owned="1", other="2"):
    """Legge lo spec e gira le lane scelte su ogni endpoint applicabile."""
    spec, err = load_spec(path)
    if err:
        return [finding("openapi:spec", path, "ERRORE", "info", "spec non caricato", err)]

    b = base_url(spec, base)
    if not b:
        return [finding("openapi:spec", path, "ERRORE", "info",
                        "nessuna base URL: passa --base oppure dichiara servers/host nello spec",
                        "base non determinabile")]

    ops = operations(spec)
    title = spec.get("info", {}).get("title", "") if isinstance(spec.get("info"), dict) else ""
    out = [finding("openapi:spec", path, f"{len(ops)} operazioni lette", "info",
                   f"spec '{title or '?'}' → base {b}",
                   "endpoint presi dal contratto, non indovinati")]

    if "check" in lanes:
        out += lane_check.run(b)                       # igiene della base, una volta

    # `idor` richiede un'identità che lo spec dichiara ma non porta: se è stata
    # chiesta la lane senza passarne una, lo diciamo (onestà) e non la eseguiamo.
    has_identity = bool(token) or bool(id_header and identity)
    if "idor" in lanes and not has_identity:
        out.append(finding("idor:spec", path, "idor non eseguito", "info",
                           "idor richiede un'identità (--token, oppure --id-header + --identity): "
                           "lo spec dichiara l'autenticazione come requisito ma non ne porta il valore",
                           "nessuna identità fornita"))

    # `jwt` richiede un token Bearer VALIDO (quello dell'utente legittimo): lo spec
    # dichiara lo schema bearer come requisito ma non ne porta il valore → arriva
    # via `--token`, esattamente come l'identità di `idor`.
    bearer_names = _bearer_schemes(spec)
    if "jwt" in lanes and not token:
        out.append(finding("jwt:spec", path, "jwt non eseguito", "info",
                           "jwt richiede un token Bearer VALIDO (--token): lo spec dichiara "
                           "lo schema bearer come requisito ma non ne porta il valore",
                           "nessun token fornito"))

    for op in ops:
        url = b + _concrete_path(op["path"])
        strings = [p for p in op["params"]
                   if (p["type"] in (None, "string")) and p["loc"] in ("query", "body", "form")]

        if "xss" in lanes:
            for p in strings:
                other_fields = {q["name"]: "aries_probe" for q in strings
                                if q["loc"] == p["loc"] and q["name"] != p["name"]}
                out.append(lane_xss.xss_reflected(
                    url, param=p["name"], method=op["method"] if p["loc"] == "query" else "POST",
                    send_as=_send_as(p["loc"]), other=other_fields))

        if "ssti" in lanes:
            # SSTI reflected-like dal contratto: lo stesso bersaglio di `xss` (ogni
            # parametro STRINGA in query/body/form), ma qui proviamo la valutazione
            # lato server di un'espressione di template (`{{887*883}}` → 783221),
            # non solo la riflessione. Lo spec dice DOVE sta il parametro e il suo
            # TRANSPORT; la lane `ssti` porta il metodo differenziale oggettivo
            # (marker+prodotto calcolato = valutato; marker+payload letterale =
            # riflesso ma non valutato → tace). Non tocca credenziali, è interamente
            # guidabile dal contratto come `xss`. NON nel default (come `nosqli`):
            # va chiesta con `--lanes …,ssti`, per non cambiare l'output di `openapi`
            # senza richiesta.
            for p in strings:
                other_fields = {q["name"]: "aries_probe" for q in strings
                                if q["loc"] == p["loc"] and q["name"] != p["name"]}
                out.append(lane_ssti.ssti_inject(
                    url, param=p["name"], method=op["method"] if p["loc"] == "query" else "POST",
                    send_as=_send_as(p["loc"]), other=other_fields))

        if "traversal" in lanes:
            # Path Traversal / LFI dal contratto: ogni parametro STRINGA che porta
            # un NOME DI FILE / PATH (file/page/path/template/…) è provato per il
            # file-read fuori radice. A differenza di `xss`/`ssti` (che provano OGNI
            # parametro stringa riflesso), `traversal` mira i soli parametri
            # FILE-LIKE — come `idor` mira i soli id-like nel path: un `username`/`q`
            # non è un file-read. La lane porta la firma OGGETTIVA (il contenuto di
            # un file di sistema noto, la sorgente PHP decodificata dal base64, il
            # prodotto RCE calcolato del data://) → un parametro riflesso crudo non
            # la produce, quindi nessun falso positivo dallo spray sui file-param.
            # Non tocca credenziali → interamente guidabile dal contratto. NON nel
            # default (come `nosqli`/`ssti`): va chiesta con `--lanes …,traversal`,
            # per non cambiare l'output di `openapi` senza richiesta.
            for p in strings:
                if not _is_file_param(p["name"]):
                    continue
                other_fields = {q["name"]: "aries_probe" for q in strings
                                if q["loc"] == p["loc"] and q["name"] != p["name"]}
                out.append(lane_traversal.traversal_probe(
                    url, param=p["name"],
                    method=op["method"] if p["loc"] == "query" else "POST",
                    send_as=_send_as(p["loc"]), other=other_fields))

        if "redirect" in lanes and op["method"].upper() == "GET":
            # OPEN REDIRECT dal contratto: una GET con un parametro di REDIRECT
            # nella query (`to`/`url`/`next`/`redirect`/`return`/…) porta l'utente
            # dove dice il valore. A differenza di xss/ssti (ogni parametro
            # stringa), `redirect` mira i soli parametri REDIRECT-like — come
            # `idor` mira i soli id-like nel path e `traversal` i soli file-param:
            # un `q`/`username` non reindirizza. La firma è OGGETTIVA (un 3xx con
            # Location verso il canary ESTERNO, mai contattato — core.probe non
            # segue i redirect), quindi un parametro riflesso crudo non la produce
            # → nessun falso positivo dallo spray sui redirect-param. Non tocca
            # credenziali → interamente guidabile dal contratto. NON nel default
            # (come nosqli/ssti/traversal): va chiesta con `--lanes …,redirect`,
            # per non cambiare l'output di `openapi` senza richiesta.
            for p in strings:
                if p["loc"] != "query" or not _is_redirect_param(p["name"]):
                    continue
                out.append(lane_redirect.redirect(url, param=p["name"]))

        if "ssrf" in lanes:
            # SSRF dal contratto: un parametro STRINGA che porta una URL che il
            # server andrà a RICHIEDERE (fetcher/webhook/importatore/anteprima).
            # A differenza di xss/ssti (ogni parametro stringa), `ssrf` mira i soli
            # parametri URL-like — come `idor` mira i soli id-like nel path,
            # `traversal` i soli file-param e `redirect` i soli redirect-like: un
            # `q`/`username`/`page` non innesca un fetch server-side. La prova è
            # OGGETTIVA e out-of-band (il canary locale colpito col nonce, non la
            # riflessione), quindi un parametro riflesso crudo non la produce → lo
            # spray sui soli URL-param non introduce falsi positivi. Il transport lo
            # dice la posizione dichiarata: query (fetcher via GET), body/form
            # (webhook via POST). Non tocca credenziali → interamente guidabile dal
            # contratto. NON nel default (come nosqli/ssti/traversal/redirect): va
            # chiesta con `--lanes …,ssrf`, per non cambiare l'output di `openapi`
            # senza richiesta.
            for p in strings:
                if not _is_url_param(p["name"]):
                    continue
                out.append(lane_ssrf.ssrf(
                    url, param=p["name"], send_as=_send_as(p["loc"]),
                    method=op["method"] if p["loc"] == "query" else "POST"))

        if "crlf" in lanes and op["method"].upper() == "GET":
            # CRLF / HTTP Response Header Injection dal contratto: una GET con un
            # parametro il cui valore può finire in un HEADER di risposta (il sink
            # canonico è il `Location` di un redirect, ma anche header costruiti da
            # una URL). A differenza di xss/ssti (ogni parametro stringa), `crlf`
            # mira i soli parametri HEADER-SINK (redirect-like ∪ url-like) — come
            # `redirect` mira i soli redirect-like e `ssrf` i soli url-like: un
            # `q`/`username` non finisce in un header. La prova è OGGETTIVA e
            # STRUTTURALE (l'header-sentinella iniettato riemerge come header di
            # risposta → il CR-LF è stato scritto grezzo e ha spezzato l'header),
            # non la riflessione nel corpo → un parametro riflesso crudo non la
            # produce, quindi lo spray sui soli header-sink non introduce falsi
            # positivi. Non tocca credenziali → interamente guidabile dal contratto.
            # NON nel default (come nosqli/ssti/traversal/redirect/ssrf): va chiesta
            # con `--lanes …,crlf`, per non cambiare l'output di `openapi` senza
            # richiesta.
            for p in strings:
                if p["loc"] != "query" or not _is_header_sink_param(p["name"]):
                    continue
                out.append(lane_crlf.crlf(url, param=p["name"]))

        if "sqli" in lanes and op["method"].lower() in _WRITE_METHODS:
            body_fields = [p for p in op["params"] if p["loc"] in ("body", "form")]
            cred = next((p for p in body_fields
                         if p["name"].lower().replace("-", "_") in CRED_FIELDS), None)
            if cred:
                other_fields = {q["name"]: "aries_probe" for q in body_fields
                                if q["name"] != cred["name"]}
                out.append(lane_attack.sqli_login(
                    url, field=cred["name"], send_as=_send_as(cred["loc"]), other=other_fields))

        if "auth" in lanes and op["method"].lower() in _WRITE_METHODS:
            # LOGIN dal contratto: un campo identità E un campo password nel corpo.
            # Il doppio requisito distingue un vero login dalla creazione di una
            # risorsa con un campo email (su cui il brute-force non avrebbe senso).
            body_fields = [p for p in op["params"] if p["loc"] in ("body", "form")]
            cred = next((p for p in body_fields
                         if p["name"].lower().replace("-", "_") in CRED_FIELDS), None)
            has_pass = any(p["name"].lower().replace("-", "_") in PASS_FIELDS
                           for p in body_fields)
            if cred and has_pass:
                # Gli altri campi (tranne identità e password, che `auth` imposta da
                # sé con valori finti) viaggiano benigni e costanti tra i tentativi.
                other_fields = {q["name"]: "aries_probe" for q in body_fields
                                if q["name"] != cred["name"]
                                and q["name"].lower().replace("-", "_") not in PASS_FIELDS}
                out.append(lane_auth.auth_bruteforce(
                    url, field=cred["name"], send_as=_send_as(cred["loc"]), other=other_fields))

        if "nosqli" in lanes and op["method"].lower() in _WRITE_METHODS:
            # LOGIN dal contratto (campo identità E campo password nel corpo, come
            # `auth`): qui proviamo la NoSQL operator-injection sul campo identità.
            # Lo spec dichiara i due campi e il TRANSPORT: un corpo application/json
            # (loc "body") → operatore nel body JSON; un form-urlencoded (loc "form")
            # → bracket-notation `campo[$op]=`. `nosqli` usa uno username FINTO
            # (operatore sempre-vero), non tocca account reali → interamente
            # guidabile dal contratto, come `auth`/`sqli`. Non è nel default: va
            # chiesta esplicitamente (`--lanes …,nosqli`), per non cambiare l'output
            # di `openapi` senza richiesta.
            body_fields = [p for p in op["params"] if p["loc"] in ("body", "form")]
            cred = next((p for p in body_fields
                         if p["name"].lower().replace("-", "_") in CRED_FIELDS), None)
            passf = next((p for p in body_fields
                          if p["name"].lower().replace("-", "_") in PASS_FIELDS), None)
            if cred and passf:
                out.append(lane_nosqli.nosqli_login(
                    url, user_field=cred["name"], pass_field=passf["name"],
                    send_as=_send_as(cred["loc"])))

        if "idor" in lanes and has_identity and op["method"].upper() == "GET":
            # IDOR dal contratto: una GET con un parametro id-like nel PATH è una
            # lettura di risorsa per-id → provo a leggere quella di un altro con la
            # MIA identità. Se più id nel path, prendo il più specifico (l'ultimo,
            # la risorsa foglia); gli altri placeholder diventano un campione.
            id_params = [p for p in op["params"]
                         if p["loc"] == "path" and _is_id_path_param(p["name"])]
            if id_params:
                keep = id_params[-1]["name"]
                iurl = b + _idor_url(op["path"], keep)
                out.append(lane_idor.idor(iurl, token=token, identity_header=id_header,
                                          identity=identity, owned=owned, other=other))

        if ("jwt" in lanes and token and op["method"].upper() == "GET"
                and _requires_bearer(op.get("security"), bearer_names)):
            # JWT dal contratto: una GET protetta da uno schema BEARER è un endpoint
            # che accetta un token → `jwt` ci prova le debolezze di verifica
            # (alg=none, chiave HS debole crackata offline, exp ignorata). A
            # differenza di xss/ssti (ogni parametro), `jwt` mira i soli endpoint che
            # lo spec dichiara protetti da Bearer — come `idor` mira i soli id-like
            # nel path. Lo spec dice DOVE il token è accettato; il suo VALORE (il
            # token legittimo) arriva via `--token`, non dal contratto. Solo GET
            # (lettura, nessun effetto collaterale), come `idor`. La prova è
            # OGGETTIVA (un token forgiato accettato con HTTP 200, o la firma
            # ricostruita offline), non la riflessione, con la guardia anti-FP della
            # lane (firma rotta rifiutata → bypass attribuibile). NON nel default
            # (come idor/nosqli/ssti/…): va chiesta con `--lanes …,jwt` + `--token`.
            out += lane_jwt.jwt_audit(url, token)

    return out


def aggregate(findings, label="openapi"):
    """Riduce la lista a UN finding con verdetto d'insieme (per il benchmark):
    VULNERABILE se almeno un sotto-finding lo è."""
    vulns = [f for f in findings if "VULNERABILE" in f.get("verdict", "")]
    if vulns:
        ev = " | ".join(f"{f['check']} @ {f['target']}" for f in vulns[:4])
        return finding(label, label, f"VULNERABILE ({len(vulns)} endpoint)", "high",
                       "la scansione guidata dallo spec ha trovato endpoint vulnerabili", ev)
    return finding(label, label, "nessun finding vulnerabile", "ok",
                   "nessun endpoint dello spec è risultato vulnerabile",
                   f"{len(findings)} controlli, 0 vulnerabili")


def run(path, base=None, lanes=DEFAULT_LANES,
        token=None, id_header=None, identity=None, owned="1", other="2"):
    return scan_spec(path, base=base, lanes=lanes, token=token,
                     id_header=id_header, identity=identity, owned=owned, other=other)
