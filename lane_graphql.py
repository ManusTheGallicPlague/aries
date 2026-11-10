"""Lane GraphQL — esposizioni tipiche di un endpoint GraphQL (OWASP A05).

Dominio: un endpoint GraphQL (transport standard POST JSON `{"query": "..."}`)
porta tre debolezze di CONFIGURAZIONE tipiche, ognuna con un segnale OGGETTIVO e
STRUTTURATO che un endpoint il quale si limita a RIFLETTERE l'input non può
produrre (la struttura della risposta È la guardia anti-falso-positivo, nello
stesso spirito del prodotto calcolato dell'SSTI o della firma del traversal):

  1. INTROSPECTION esposta (`graphql:introspection`, ALTO) — la query di
     introspezione `{__schema{queryType{name} types{name}}}` restituisce lo
     schema completo (ogni tipo e campo dell'API). In produzione è una
     misconfigurazione: regala all'attaccante la mappa dell'intera superficie.
     Segnale: la risposta è un JSON con `data.__schema.queryType.name` (stringa
     non vuota) E `data.__schema.types` (lista non vuota) → una VERA risposta di
     introspezione, non l'eco della query inviata.

  2. FIELD SUGGESTION attiva (`graphql:suggestions`, MEDIO) — anche con
     l'introspezione DISABILITATA, graphql-js (e motori simili) perdono i nomi
     dei campi nei messaggi d'errore: su un campo scritto male suggeriscono "Did
     you mean …". Mandiamo una query con un typo del meta-campo universale
     `__typename` (`{__typenam}`): se la risposta è un errore GraphQL (`errors[]`)
     il cui messaggio contiene "Did you mean", il server sta suggerendo i nomi
     reali → leak dello schema a introspezione spenta. Il segnale è
     SERVER-GENERATO: il typo che inviamo non contiene la frase né il nome esatto.

  3. QUERY BATCHING senza limite (`graphql:batching`, BASSO) — un array di N
     query in una sola richiesta HTTP viene eseguito TUTTO: amplifica il
     brute-force (N tentativi per richiesta → aggira i rate-limit per-richiesta)
     e il DoS. Inviamo `[{query},{query},{query}]` e guardiamo se la risposta è
     una LISTA di N risultati GraphQL (ogni elemento un dict con `data` o
     `errors`). Un endpoint che fa l'ECO rimanderebbe gli elementi `{"query": …}`
     (chiave `query`, non `data`/`errors`) → la guardia strutturale TACE.

  4. MUTATION eseguibili via GET (`graphql:get-transport`, MEDIO) — il transport
     standard è POST JSON, ma un endpoint che esegue una MUTATION (operazione che
     cambia stato) inviata via `GET ?query=…` è forgeable CROSS-SITE: il browser
     allega da solo il cookie di sessione e una GET "semplice" non fa preflight →
     basta un `<img src=…>` sul sito dell'attaccante = CSRF. La best practice
     (OWASP) è vietare le mutation su GET; le query in sola lettura su GET sono
     ammesse (per il caching) e NON vengono segnalate. Sonda SENZA effetti
     collaterali: `mutation{__typename}` chiede solo il nome del tipo radice delle
     mutation (meta-campo universale, non muta nulla). Segnale OGGETTIVO: se la
     risposta è un risultato ESEGUITO (`data.__typename` stringa non vuota,
     generata dal server) la mutation è stata eseguita via GET → un endpoint che
     riflette la query-string non può produrre quella struttura.

  5. MUTATION eseguibili via FORM POST (`graphql:form-transport`, MEDIO) — il
     transport standard POST `application/json` NON è CORS-"semplice" (fa scattare
     un preflight = argine CSRF); ma un endpoint che esegue una MUTATION inviata
     come `application/x-www-form-urlencoded` (campo form `query=…`) è forgeable
     CROSS-SITE col vettore CSRF più classico: un `<form>` ad auto-submit sul sito
     dell'attaccante manda la mutation senza token e senza preflight (il
     content-type form è semplice), col cookie di sessione allegato dal browser. È
     il gemello del transport GET, su un content-type CORS-semplice diverso. Stessa
     sonda senza effetti (`mutation{__typename}`) e stesso segnale strutturato
     (`data.__typename` server-generato = mutation eseguita → guardia anti-eco).

`graphql_audit` ritorna i cinque finding; `_worst` riduce a un verdetto unico
per il benchmark (come lane_tls/lane_jwt). ATTIVO: manda query, SOLO host in
ALLOWLIST (il confine vive in core.probe). Limite onesto: copre il transport
STANDARD — POST `application/json` con body `{"query": "..."}` (il più diffuso) —
la variante GET `?query=` e il form POST `application/x-www-form-urlencoded` per la
CSRF da mutation; il transport `Content-Type: application/graphql` resta fuori
scope del modello minimale.
"""

import json
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl

from core import finding, probe, as_curl, SEV_ORDER

_N_BATCH = 3   # quante query nel test di batching (una sola richiesta HTTP)


def _post(url, body_obj, session=None):
    """POST JSON di `body_obj` (dict per la query singola, list per il batch) →
    (url, headers, body, risposta). La stessa tripla serve a mandare la richiesta
    E a generare il PoC curl, così non possono divergere. `session`
    (Cookie/Bearer/header) raggiunge l'eventuale superficie LOGGATA."""
    h = {"Content-Type": "application/json"}
    b = json.dumps(body_obj)
    return url, h, b, probe(url, "POST", h, b, session=session)


def _json_body(resp):
    """Il corpo della risposta parsato come JSON (dict o list), o None se non è
    JSON valido / la probe è andata in errore. È il parsing a fare da guardia: un
    endpoint che riflette una stringa non produce la STRUTTURA attesa."""
    if "error" in resp:
        return None
    try:
        return json.loads(resp.get("body_head", "") or "")
    except Exception:
        return None


def _introspection_check(url, session=None):
    """Introspezione aperta? La query di introspezione restituisce lo schema.
    Segnale OGGETTIVO: `data.__schema.queryType.name` (str non vuota) E
    `data.__schema.types` (lista non vuota) — una struttura che una semplice eco
    della query NON può produrre."""
    q = "query{__schema{queryType{name} types{name}}}"
    u, h, b, resp = _post(url, {"query": q}, session=session)
    j = _json_body(resp)
    schema = j.get("data", {}).get("__schema") if isinstance(j, dict) else None
    if isinstance(schema, dict):
        qt = (schema.get("queryType") or {}).get("name")
        types = schema.get("types")
        if isinstance(qt, str) and qt and isinstance(types, list) and types:
            names = [t.get("name") for t in types if isinstance(t, dict)]
            return finding(
                "graphql:introspection", url,
                "VULNERABILE (introspection esposta)", "high",
                "la query di introspezione restituisce lo schema completo → "
                "l'attaccante ottiene la mappa dell'intera API (ogni tipo e "
                "campo); in produzione l'introspezione va disabilitata",
                f"data.__schema.queryType.name={qt!r}, {len(types)} tipi esposti: "
                + ", ".join(str(n) for n in names[:8]),
                as_curl(u, "POST", h, b, session=session))
    return finding(
        "graphql:introspection", url, "introspection disabilitata", "ok",
        "la query di introspezione non restituisce uno schema strutturato "
        "(introspezione spenta o endpoint non-GraphQL)",
        f"risposta HTTP {resp.get('status')}: nessun data.__schema valido")


def _suggestions_check(url, session=None):
    """Field suggestion attiva? Un typo del meta-campo universale `__typename`
    fa suggerire al server il nome reale ("Did you mean …") → leak dei nomi di
    campo anche con l'introspezione spenta. Segnale SERVER-GENERATO: il typo che
    inviamo non contiene la frase né il nome esatto."""
    u, h, b, resp = _post(url, {"query": "{__typenam}"}, session=session)
    j = _json_body(resp)
    errs = j.get("errors") if isinstance(j, dict) else None
    if isinstance(errs, list):
        for e in errs:
            msg = e.get("message", "") if isinstance(e, dict) else ""
            if "did you mean" in str(msg).lower():
                return finding(
                    "graphql:suggestions", url,
                    "VULNERABILE (field suggestion attiva)", "med",
                    "il server suggerisce i nomi dei campi reali nei messaggi "
                    "d'errore ('Did you mean') → leak dello schema anche con "
                    "l'introspezione disabilitata; disattivare le suggestion",
                    f"errore su campo inesistente: {str(msg)[:160]}",
                    as_curl(u, "POST", h, b, session=session))
    return finding(
        "graphql:suggestions", url, "nessuna field suggestion", "ok",
        "il server non suggerisce nomi di campo sugli errori (suggestion spente "
        "o endpoint non-GraphQL)",
        f"risposta HTTP {resp.get('status')}: nessun 'Did you mean' negli errori")


def _batching_check(url, session=None):
    """Query batching senza limite? Un array di N query viene eseguito tutto.
    Segnale OGGETTIVO: la risposta è una LISTA di N risultati GraphQL (ogni
    elemento un dict con `data` o `errors`). Guardia anti-eco: un endpoint che
    riflette rimanderebbe gli elementi inviati `{"query": …}` (chiave `query`,
    non `data`/`errors`) → la guardia strutturale tace."""
    batch = [{"query": "{__typename}"} for _ in range(_N_BATCH)]
    u, h, b, resp = _post(url, batch, session=session)
    j = _json_body(resp)
    if isinstance(j, list) and len(j) == _N_BATCH \
            and all(isinstance(x, dict) and ("data" in x or "errors" in x) for x in j):
        return finding(
            "graphql:batching", url,
            "VULNERABILE (query batching senza limite)", "low",
            f"il server esegue un array di {_N_BATCH} query in una sola richiesta "
            "HTTP → amplifica il brute-force (aggira i rate-limit per-richiesta) e "
            "il DoS; limitare o disabilitare il batching delle query",
            f"inviate {_N_BATCH} query in un array, ricevuti {len(j)} risultati "
            "GraphQL distinti (ognuno con data/errors)",
            as_curl(u, "POST", h, b, session=session))
    shape = f"lista di {len(j)}" if isinstance(j, list) else type(j).__name__
    return finding(
        "graphql:batching", url, "batching non eseguito", "ok",
        "un array di query non viene eseguito come batch (batching disabilitato "
        "o risposta non conforme a N risultati)",
        f"risposta: {shape}, non {_N_BATCH} risultati GraphQL")


def _get(url, query, session=None):
    """GET `url?query=<query>` — transport GET di GraphQL. L'operazione viaggia
    nella QUERY-STRING (non nel corpo): è così che un endpoint GraphQL esposto su
    GET esegue le operazioni. Ritorna (url_completo, risposta); lo stesso url
    completo serve a mandare la richiesta E a generare il PoC curl → non possono
    divergere. `session` raggiunge l'eventuale superficie LOGGATA."""
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    qs.append(("query", query))
    full = urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(qs), parts.fragment))
    return full, probe(full, "GET", session=session)


def _get_transport_check(url, session=None):
    """Mutation eseguibili via GET? Il transport standard è POST JSON; una
    MUTATION inviata via `GET ?query=…` è forgeable CROSS-SITE (cookie allegato
    dal browser, nessun preflight su una GET semplice → `<img src=…>` = CSRF). La
    sonda è SENZA effetti collaterali: `mutation{__typename}` chiede solo il NOME
    del tipo radice delle mutation (meta-campo universale, non muta nulla).
    Segnale OGGETTIVO e STRUTTURATO: `data.__typename` stringa non vuota = una
    mutation È STATA eseguita via GET — un endpoint che riflette la query-string
    non può produrre quella struttura (guardia anti-eco, come le altre tre sonde).
    Le query in sola lettura su GET (ammesse per il caching) NON vengono segnalate:
    il vettore CSRF è la MUTATION, ed è quella che la sonda invia."""
    full, resp = _get(url, "mutation{__typename}", session=session)
    j = _json_body(resp)
    tn = j.get("data", {}).get("__typename") if isinstance(j, dict) else None
    if isinstance(tn, str) and tn:
        return finding(
            "graphql:get-transport", url,
            "VULNERABILE (mutation via GET → CSRF)", "med",
            "il server esegue le MUTATION inviate via GET `?query=…` → sono "
            "forgeable cross-site (il browser allega il cookie di sessione da "
            "solo, una GET semplice non fa preflight: basta un `<img src=…>` sul "
            "sito dell'attaccante); vietare le mutation sul transport GET (le "
            "query in sola lettura possono restare, per il caching)",
            f"GET {full} → data.__typename={tn!r}: una mutation è stata ESEGUITA "
            "via GET (sonda senza effetti: chiede solo il nome del tipo radice)",
            as_curl(full, "GET", session=session))
    return finding(
        "graphql:get-transport", url, "mutation via GET non eseguita", "ok",
        "una mutation inviata via GET `?query=…` non viene eseguita (transport "
        "GET vietato alle mutation, o endpoint non-GraphQL): nessuna superficie "
        "CSRF via GET",
        f"GET con ?query=mutation{{__typename}}: nessun data.__typename eseguito "
        f"(HTTP {resp.get('status')})")


def _form_transport_check(url, session=None):
    """Mutation eseguibili via FORM POST (CORS-"semplice")? Il transport standard
    è POST `application/json`, che NON è un content-type CORS-semplice → una
    richiesta cross-site lo fa precedere da un preflight OPTIONS (argine CSRF
    implicito). Ma un endpoint che esegue le mutation anche quando il corpo arriva
    come `application/x-www-form-urlencoded` (campo form `query=…`) espone un
    vettore CSRF più classico del transport GET: un `<form>` ad auto-submit sul
    sito dell'attaccante manda la mutation SENZA token e SENZA preflight (il
    content-type form È CORS-semplice), col cookie di sessione allegato dal browser.
    Sonda SENZA effetti collaterali: `mutation{__typename}` chiede solo il NOME del
    tipo radice delle mutation (meta-campo universale, non muta nulla). Segnale
    OGGETTIVO e STRUTTURATO, come le altre sonde: `data.__typename` stringa non
    vuota = la mutation È STATA eseguita via form POST → un endpoint che riflette il
    corpo form non può produrre quella struttura (guardia anti-eco). Best practice
    (OWASP): accettare le mutation SOLO su `application/json`, così il preflight
    CORS scatta e la forgiatura via form semplice è bloccata."""
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    b = urlencode({"query": "mutation{__typename}"})
    resp = probe(url, "POST", h, b, session=session)
    j = _json_body(resp)
    tn = j.get("data", {}).get("__typename") if isinstance(j, dict) else None
    if isinstance(tn, str) and tn:
        return finding(
            "graphql:form-transport", url,
            "VULNERABILE (mutation via form POST → CSRF)", "med",
            "il server esegue le MUTATION inviate come "
            "`application/x-www-form-urlencoded` (campo form `query=…`) → sono "
            "forgeable cross-site: un `<form>` ad auto-submit sul sito "
            "dell'attaccante invia la mutation senza token e senza preflight (il "
            "content-type form è CORS-semplice), col cookie di sessione allegato "
            "dal browser; accettare le mutation SOLO su `application/json` (così "
            "il preflight CORS scatta e la richiesta cross-site è bloccata)",
            f"POST {url} (Content-Type: application/x-www-form-urlencoded, body "
            f"`{b}`) → data.__typename={tn!r}: una mutation è stata ESEGUITA via "
            "form POST (sonda senza effetti: chiede solo il nome del tipo radice)",
            as_curl(url, "POST", h, b, session=session))
    return finding(
        "graphql:form-transport", url, "mutation via form POST non eseguita", "ok",
        "una mutation inviata come `application/x-www-form-urlencoded` non viene "
        "eseguita (le mutation richiedono `application/json`, che fa scattare il "
        "preflight CORS → non forgeable via form semplice): nessuna superficie "
        "CSRF via form POST",
        f"POST form-urlencoded con query=mutation{{__typename}}: nessun "
        f"data.__typename eseguito (HTTP {resp.get('status')})")


def graphql_audit(url, session=None):
    """Audit GraphQL del bersaglio → [introspection, suggestions, batching,
    get-transport, form-transport].
    ATTIVO: POST query, confine ALLOWLIST imposto in core.probe. Una probe di
    apertura distingue il bersaglio irraggiungibile / fuori ALLOWLIST (→ ERRORE
    onesto) dall'introspezione spenta (→ ok): non si finge un verdetto su ciò che
    non si è raggiunto."""
    _, _, _, first = _post(url, {"query": "{__typename}"}, session=session)
    if "error" in first:
        return [finding(
            "graphql:introspection", url, "ERRORE", "info",
            "probe fallita (host fuori ALLOWLIST o irraggiungibile): nessun "
            "verdetto", str(first["error"]))]
    return [_introspection_check(url, session=session),
            _suggestions_check(url, session=session),
            _batching_check(url, session=session),
            _get_transport_check(url, session=session),
            _form_transport_check(url, session=session)]


def _worst(findings):
    """Il finding PEGGIORE (per severità) dell'audit — riduce la lane a un
    verdetto unico per il benchmark, come lane_tls/lane_jwt._worst."""
    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))[0]


def run(url, session=None):
    return graphql_audit(url, session=session)
