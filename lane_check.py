"""Lane CHECK — igiene web deterministica, SOLA LETTURA (solo GET).

Ogni controllo ritorna un Finding con la prova. Niente LLM: i fatti li legge
il codice dalla risposta vera. Migrata dal primo nucleo di ARIES.
"""

import re
from urllib.parse import urlparse

import config
from core import finding, probe, as_curl

# Ogni header chiude una classe d'attacco reale (anche mini-lezione).
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS — forza il browser a usare solo HTTPS, chiude l'SSL-strip", "med"),
    "content-security-policy":   ("CSP — limita da dove arrivano script/risorse: argine a XSS e injection", "med"),
    "x-content-type-options":    ("nosniff — vieta al browser di 'indovinare' il tipo di contenuto", "low"),
    "x-frame-options":           ("anti-clickjacking — niente iframe ostili", "low"),
    "referrer-policy":           ("limita quanto dell'URL trapela nel Referer", "low"),
    "permissions-policy":        ("spegne API del browser non usate (camera, microfono, geo)", "low"),
}

# LEZIONE (imparata su Juice Shop): un 200 NON basta. Una SPA risponde 200 +
# index.html per OGNI path → falso positivo. "Esposto" solo se 200 + contenuto
# NON-HTML + firma del file vero.
SENSITIVE_PATHS = {
    "/.git/config":    lambda b: "[core]" in b or "repositoryformatversion" in b,
    "/.git/HEAD":      lambda b: b.strip().startswith("ref:"),
    "/.env":           lambda b: "=" in b and "<" not in b[:40],
    "/metrics":        lambda b: "# HELP" in b or "# TYPE" in b,
    "/server-status":  lambda b: "Apache" in b and "Status" in b,
    "/config.php.bak": lambda b: "<?php" in b or "define(" in b,
    "/.ht_passwd":     lambda b: ":" in b and "<" not in b[:40],
}


def _headers(base, session=None):
    p = probe(base, session=session)
    if "error" in p:
        return [finding("security-headers", base, "ERRORE", "info", "probe fallita", p["error"])]
    h = p["headers"]
    out = []
    for name, (why, sev) in SECURITY_HEADERS.items():
        present = name in h
        out.append(finding(
            f"header:{name}", base,
            "presente" if present else "MANCANTE",
            "ok" if present else sev, why,
            f"{name}: {h[name]}" if present else "(assente nella risposta)"))
    # Controllo di VALORE complementare: se l'HSTS c'è, `max-age=0` lo DISATTIVA
    # (il browser dimentica la policy) → difesa inerte benché l'header sia
    # presente. Lo emettiamo solo quando l'header esiste (come `cookie-samesite`
    # esiste solo in presenza di un cookie): l'assenza dell'header è già segnalata
    # sopra come MANCANTE → non la raddoppiamo.
    hsts_raw = h.get("strict-transport-security", "")
    if hsts_raw:
        has_def, age = hsts_active(hsts_raw)
        out.append(finding(
            "hsts-maxage", base,
            "HSTS attivo" if has_def else "HSTS DISATTIVATO",
            "ok" if has_def else "med",
            "max-age>0 impone HTTPS; max-age=0 (o assente) ordina al browser di "
            "DIMENTICARE la policy → difesa HSTS inerte benché l'header sia "
            "presente (complementa il controllo di presenza)",
            f"max-age={age}" if age is not None
            else "(max-age assente/non numerico nel valore Strict-Transport-Security)"))
    # Stesso falso negativo di VALORE applicato alla CSP: una policy PRESENTE può
    # essere inerte contro l'XSS (`script-src 'unsafe-inline'` senza nonce/hash, o
    # nessun `script-src`/`default-src`). Emesso solo quando l'header esiste
    # (l'assenza è già `header:content-security-policy MANCANTE` → non la si
    # raddoppia), come `hsts-maxage` e `cookie-samesite`.
    csp_raw = h.get("content-security-policy", "")
    if csp_raw:
        has_def, motivo = csp_xss_active(csp_raw)
        out.append(finding(
            "csp-xss", base,
            "CSP efficace contro XSS" if has_def else "CSP INERTE contro XSS",
            "ok" if has_def else "med",
            "una CSP con script-src 'unsafe-inline' (senza nonce/hash), o priva di "
            "script-src/default-src, NON ferma l'esecuzione di script inline "
            "iniettati → argine XSS inerte benché l'header sia presente "
            "(complementa il controllo di presenza)",
            f"Content-Security-Policy: {csp_raw}" if has_def
            else f"{motivo} — Content-Security-Policy: {csp_raw}"))
    # Stesso falso negativo di VALORE applicato a X-Content-Type-Options: l'UNICO
    # valore che disabilita il MIME-sniffing è `nosniff` (i browser ignorano ogni
    # altro valore). Un header PRESENTE ma con un valore diverso (`none`, `sniff`,
    # vuoto, …) è inerte — il browser continua a INDOVINARE il tipo di contenuto.
    # Emesso solo quando l'header esiste (l'assenza è già
    # `header:x-content-type-options MANCANTE` → non la si raddoppia), come
    # `hsts-maxage`/`csp-xss`/`cookie-samesite`.
    xcto_raw = h.get("x-content-type-options", "")
    if xcto_raw:
        has_def, tok = xcto_active(xcto_raw)
        out.append(finding(
            "xcto-nosniff", base,
            "nosniff attivo" if has_def else "NOSNIFF INERTE",
            "ok" if has_def else "low",
            "l'unico valore efficace di X-Content-Type-Options è `nosniff`: ogni "
            "altro valore lascia il browser a INDOVINARE il tipo di contenuto "
            "(MIME-sniffing → XSS da upload, drive-by) → header presente ma difesa "
            "inerte (complementa il controllo di presenza)",
            f"X-Content-Type-Options: {xcto_raw}"))
    # Stesso falso negativo di VALORE applicato a X-Frame-Options: gli UNICI valori
    # che difendono dal clickjacking sono `DENY` e `SAMEORIGIN`. Il deprecato
    # `ALLOW-FROM <uri>` è IGNORATO dai browser moderni → l'header è presente ma
    # NON protegge dal framing ostile; ogni altro valore è ugualmente inerte.
    # Emesso solo quando l'header esiste (l'assenza è già
    # `header:x-frame-options MANCANTE` → non la si raddoppia), come
    # `xcto-nosniff`/`hsts-maxage`/`csp-xss`/`cookie-samesite`.
    xfo_raw = h.get("x-frame-options", "")
    if xfo_raw:
        has_def, directive = xfo_active(xfo_raw)
        out.append(finding(
            "xfo-clickjack", base,
            "anti-clickjacking attivo" if has_def else "X-FRAME-OPTIONS INERTE",
            "ok" if has_def else "low",
            "gli unici valori efficaci di X-Frame-Options sono `DENY` e "
            "`SAMEORIGIN`: il deprecato `ALLOW-FROM` è IGNORATO dai browser "
            "moderni, e ogni altro valore non limita il framing → header presente "
            "ma difesa anti-clickjacking inerte (complementa il controllo di "
            "presenza; la CSP `frame-ancestors` è la difesa gemella che può "
            "coprire il caso anche con un XFO inerte)",
            f"X-Frame-Options: {xfo_raw}"))
    return out


def hsts_active(hsts_value):
    """Valuta se il VALORE di un header `Strict-Transport-Security` fornisce una
    difesa HSTS reale. `max-age=0` DISATTIVA l'HSTS: ordina al browser di
    *dimenticare* la policy (è l'idioma canonico per spegnerlo) → l'header è
    presente ma NON protegge dall'SSL-strip. È il falso negativo che il controllo
    sulla sola *presenza* non vede (un `max-age=0` presente lo soddisfaceva pur
    non difendendo da nulla, esattamente come un `SameSite=None` presente).
    Un `max-age` assente o non numerico è ugualmente inerte (la direttiva è
    ignorata dal browser). Complementare al controllo di presenza
    `header:strict-transport-security`: qui la prova è il VALORE. Ritorna
    `(ha_difesa, max_age)` con `max_age` int, o `None` se assente/non valido."""
    m = re.search(r"max-age\s*=\s*\"?(\d+)\"?", hsts_value, re.IGNORECASE)
    if not m:
        return (False, None)                     # max-age assente/non numerico → inerte
    age = int(m.group(1))
    return (age > 0, age)                         # max-age=0 → HSTS disattivato


def _policy_blocks_inline(policy):
    """Una singola policy CSP blocca l'esecuzione di uno script INLINE iniettato?
    La direttiva che governa gli script è `script-src`; se assente vale
    `default-src` come fallback (semantica CSP). Ritorna `(blocca, motivo)` con
    `motivo` non vuoto solo quando NON blocca (oggettivamente inerte)."""
    dirs = {}
    for part in policy.split(";"):
        toks = part.split()
        if toks:
            dirs[toks[0].lower()] = [t.lower() for t in toks[1:]]
    src = dirs.get("script-src")
    if src is None:
        src = dirs.get("default-src")
    if src is None:
        # Nessuna direttiva governa gli script → non limitati → inline esegue.
        return (False, "né script-src né default-src presenti → script non limitati")
    has_unsafe_inline = "'unsafe-inline'" in src
    # Con un nonce o un hash presente i browser CSP2+ IGNORANO 'unsafe-inline'
    # (fallback di retro-compatibilità, non un buco) → NON inerte.
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in src)
    if has_unsafe_inline and not has_nonce_or_hash:
        return (False, "script-src con 'unsafe-inline' e senza nonce/hash → script inline iniettati eseguiti")
    return (True, "")


def csp_xss_active(csp_value):
    """Valuta se il VALORE di un header `Content-Security-Policy` fornisce una
    difesa REALE contro l'XSS, o è presente ma inerte. Il controllo sulla sola
    PRESENZA (`header:content-security-policy`) direbbe "presente/ok" anche per
    una policy che non ferma l'XSS → falso senso di sicurezza, stessa classe di
    `hsts-maxage` e `cookie-samesite`. Qui la prova è il VALORE.

    Casi OGGETTIVAMENTE inerti contro l'XSS (fatti del linguaggio CSP, non soglie
    di policy):
      - la direttiva effettiva (`script-src`, o `default-src` come fallback)
        contiene `'unsafe-inline'` SENZA alcun nonce/hash → gli script inline
        (e gli handler `on*`) iniettati ESEGUONO;
      - né `script-src` né `default-src` presenti → gli script non sono limitati.

    `'unsafe-eval'` da solo NON è inerte contro l'XSS inline (la CSP blocca
    comunque uno `<script>` iniettato: indebolisce i soli sink basati su `eval`) →
    NON ribalta il verdetto (onestà: ci si ferma ai valori oggettivamente inerti).

    Più policy nello stesso header (separate da virgole) sono imposte in
    INTERSEZIONE dal browser: uno script inline deve essere ammesso da OGNI policy
    → la CSP è inerte solo se NESSUNA policy lo blocca. Ritorna `(ha_difesa,
    motivo)` con `motivo` la ragione dell'inerzia (o '' se difende)."""
    policies = [p for p in csp_value.split(",") if p.strip()]
    if not policies:
        return (False, "CSP vuota")
    reasons = []
    for pol in policies:
        blocca, motivo = _policy_blocks_inline(pol)
        if blocca:
            return (True, "")          # una policy blocca l'inline → difesa presente
        reasons.append(motivo)
    return (False, reasons[0])          # nessuna policy blocca → inerte


def xcto_active(xcto_value):
    """Valuta se il VALORE di un header `X-Content-Type-Options` disabilita
    davvero il MIME-sniffing. L'UNICO valore efficace è `nosniff` (fatto del
    linguaggio, non una soglia di policy): i browser seguono l'algoritmo
    "determine nosniff" di WHATWG Fetch — prendono il PRIMO token (la lista è
    separata da virgole), lo confrontano case-insensitive con `nosniff` e
    IGNORANO ogni altro valore. Un header presente con un valore diverso
    (`none`, `sniff`, vuoto, o `nosniff` NON in prima posizione) è quindi
    presente ma INERTE: il browser continua a indovinare il tipo di contenuto.
    È il falso negativo che il controllo sulla sola PRESENZA non vede (un valore
    qualunque lo soddisfa pur non difendendo da nulla, come `max-age=0` per
    l'HSTS). Complementare al controllo di presenza
    `header:x-content-type-options`: qui la prova è il VALORE. Ritorna
    `(ha_difesa, primo_token)` col primo token normalizzato (minuscolo)."""
    first = xcto_value.split(",")[0].strip().lower()
    return (first == "nosniff", first)


def xfo_active(xfo_value):
    """Valuta se il VALORE di un header `X-Frame-Options` fornisce una difesa
    anti-clickjacking reale. Gli UNICI valori efficaci sono `DENY` e `SAMEORIGIN`
    (fatti del linguaggio, non soglie di policy). Il deprecato `ALLOW-FROM <uri>`
    è IGNORATO dai browser moderni (Chrome, Safari, Firefox 70+) → l'header è
    presente ma NON protegge dal framing ostile; ogni altro valore (vuoto,
    `ALLOWALL`, garbage) è ugualmente inerte. È il falso negativo che il controllo
    sulla sola PRESENZA non vede (un `ALLOW-FROM` presente lo soddisfaceva pur
    non difendendo da nulla, come `max-age=0` per l'HSTS o `none` per il nosniff).
    Complementare al controllo di presenza `header:x-frame-options`: qui la prova
    è il VALORE.

    Nota onestà: X-Frame-Options è una delle due difese anti-clickjacking; la CSP
    `frame-ancestors` la rimpiazza (defense-in-depth) e può coprire il caso anche
    con un XFO inerte → qui si afferma che il VALORE dell'header XFO è inerte, NON
    che la pagina sia clickjackable. Ci si ferma al valore oggettivamente inerte
    (≠ `DENY`/`SAMEORIGIN`, incluso il deprecato `ALLOW-FROM`), non a una soglia
    di policy. Ritorna `(ha_difesa, direttiva)` con la direttiva (primo token,
    normalizzata minuscolo)."""
    low = xfo_value.strip().lower()
    directive = re.split(r"[\s,]", low, 1)[0] if low else ""
    return (directive in ("deny", "sameorigin"), directive)


def samesite_csrf(set_cookie):
    """Valuta se l'attributo `SameSite` di un header `Set-Cookie` fornisce una
    difesa CSRF passiva. `SameSite=Lax`/`Strict` impedisce al browser di
    allegare il cookie di sessione sulle richieste cross-site che cambiano
    stato → argine CSRF. `SameSite=None` (o attributo ASSENTE) NON protegge:
    è il buco che il check sulla sola *presenza* della stringa 'samesite' non
    vedeva (un `SameSite=None` lo soddisfaceva pur non difendendo da nulla).
    Complementare alla lane ATTIVA `csrf` (che prova l'enforcement del token):
    qui la prova è passiva, dal solo header. Ritorna `(ha_difesa, valore)` con
    `valore` il token SameSite in minuscolo o `None` se l'attributo manca."""
    m = re.search(r"samesite\s*=\s*([a-zA-Z]+)", set_cookie, re.IGNORECASE)
    if not m:
        return (False, None)                     # attributo assente → nessuna difesa
    val = m.group(1).lower()
    return (val in ("lax", "strict"), val)        # None (o ignoto) → nessuna difesa


def _cookies(base, session=None):
    p = probe(base, session=session)
    if "error" in p:
        return [finding("cookie-flags", base, "ERRORE", "info", "probe fallita", p["error"])]
    sc = p["headers"].get("set-cookie", "")
    if not sc:
        return [finding("cookie-flags", base, "n/d", "info",
                        "la root non imposta cookie (si valuta sul login)", "(nessun Set-Cookie)")]
    low = sc.lower()
    missing = [f for f in ("secure", "httponly", "samesite") if f not in low]
    flags = finding("cookie-flags", base,
                    "robusti" if not missing else "DEBOLI",
                    "ok" if not missing else "med",
                    "un cookie di sessione va Secure + HttpOnly + SameSite",
                    f"flag mancanti: {missing}" if missing else "Secure + HttpOnly + SameSite presenti")
    # Controllo passivo COMPLEMENTARE alla lane attiva `csrf`: non basta che
    # l'attributo SameSite ci sia, deve VALERE Lax/Strict. `SameSite=None` (o
    # assente) lascia il cookie di sessione allegabile cross-site → difesa CSRF
    # mancante. Distinto da `cookie-flags` (presenza) perché risponde a un'altra
    # domanda: il VALORE protegge davvero dal CSRF?
    has_def, val = samesite_csrf(sc)
    csrf = finding("cookie-samesite", base,
                   "difesa CSRF presente" if has_def else "DIFESA CSRF ASSENTE",
                   "ok" if has_def else "med",
                   "SameSite=Lax/Strict blocca l'invio cross-site del cookie di sessione "
                   "(argine CSRF passivo; complementa la lane attiva `csrf`)",
                   f"SameSite={val}" if val else "(attributo SameSite assente nel Set-Cookie)")
    return [flags, csrf]


def _banner(base, session=None):
    p = probe(base, session=session)
    if "error" in p:
        return finding("server-banner", base, "ERRORE", "info", "probe fallita", p["error"])
    srv = p["headers"].get("server", "")
    if not srv:
        return finding("server-banner", base, "assente", "ok",
                       "nessun header Server: non regala la versione", "(nessun Server)")
    verbose = any(ch.isdigit() for ch in srv)
    return finding("server-banner", base, "verboso" if verbose else "sobrio",
                   "low" if verbose else "ok",
                   "il banner rivela la versione → facilita la ricerca di CVE" if verbose
                   else "banner senza versione", f"Server: {srv}")


def _exposure(base, session=None):
    base = base.rstrip("/")
    out = []
    for path, sig in SENSITIVE_PATHS.items():
        p = probe(base + path, session=session)
        if "error" in p:
            continue
        body, ctype = p.get("body_head", ""), p["headers"].get("content-type", "")
        is_html = "text/html" in ctype or body.lstrip()[:1] == "<"
        exposed = p["status"] == 200 and not is_html and sig(body)
        if exposed:
            v, s, n = "ESPOSTO", "high", "file sensibile servito col CONTENUTO reale"
        elif p["status"] == 200 and is_html:
            v, s, n = "non esposto", "ok", "200 ma è HTML/SPA, non il file: falso positivo evitato"
        else:
            v, s, n = "non esposto", "ok", "non accessibile"
        repro = as_curl(base + path, session=session) if exposed else ""
        out.append(finding(f"exposure:{path}", base + path, v, s, n,
                           f"HTTP {p['status']} · ct={ctype or '?'}", repro))
    return out


def _gate(url, expect, kind, session=None):
    p = probe(url, session=session)
    if "error" in p:
        return finding(f"{kind}:{url}", url, "ERRORE", "info", "probe fallita", p["error"])
    st = str(p["status"])
    loc = p["headers"].get("location", "")
    ok = st in expect
    return finding(f"{kind}:{urlparse(url).path or url}", url,
                   "chiuso" if ok else "APERTO — da indagare",
                   "ok" if ok else "high",
                   f"senza credenziali atteso status fra {expect}",
                   f"HTTP {st}" + (f" → {loc}" if loc else ""))


def run(base, session=None):
    # `session` (Cookie/Bearer/header custom) raggiunge la superficie LOGGATA:
    # l'igiene (header di sicurezza, cookie, banner, esposizioni) viene valutata
    # sulla pagina AUTENTICATA, non solo sul login wall pubblico.
    host = (urlparse(base).hostname or "").lower()
    prof = config.PROFILES.get(host, {"api": [], "protected": []})
    f = []
    f += _headers(base, session=session)
    f += _cookies(base, session=session)
    f.append(_banner(base, session=session))
    f += _exposure(base, session=session)
    b = base.rstrip("/")
    for ep in prof["api"]:
        f.append(_gate(b + ep, ("401", "403"), "api-gate", session=session))
    for ep in prof["protected"]:
        f.append(_gate(b + ep, ("401", "403", "302"), "auth-gate", session=session))
    return f
