"""ARIES — base condivisa da tutte le lane: probe HTTP, Finding, report.

Principio: i FATTI nascono qui (codice), con l'evidenza accanto. Le lane
costruiscono Finding; il motore li stampa in testo o JSON. L'LLM, quando c'è,
legge il JSON e interpreta — non produce i fatti.
"""

import json
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

import config


# --- probe HTTP deterministico (non segue i redirect: vogliamo VEDERE il 302) -
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def probe(url, method="GET", headers=None, body=None, timeout=None, session=None):
    """Una richiesta HTTP, SOLO verso host in ALLOWLIST (il confine vive qui,
    così nessuna lane lo può aggirare). Misura anche il tempo (serve ai test
    time-based). Ritorna sempre un dict; mai un'eccezione fuori.

    `session`: dict di header di SESSIONE (Cookie / Authorization: Bearer /
    header custom) da allegare a OGNI richiesta → consente alle lane di testare
    la superficie LOGGATA (dietro l'autenticazione), oggi quasi mai coperta. Gli
    header della sessione sono fusi SOTTO gli `headers` della richiesta, così un
    header esplicito della lane (es. Content-Type) vince sempre sul collide. Il
    confine resta qui: la sessione non aggira l'ALLOWLIST, aggiunge solo
    credenziali verso lo stesso host autorizzato."""
    host = (urlparse(url).hostname or "").lower()
    if host not in config.ALLOWLIST:
        return {"error": f"host '{host}' fuori ALLOWLIST (rifiutato)"}
    data = body.encode() if isinstance(body, str) else body
    eff_headers = {**(session or {}), **(headers or {})}
    req = urllib.request.Request(url, method=method, data=data, headers=eff_headers)
    t0 = time.perf_counter()
    try:
        r = _OPENER.open(req, timeout=timeout or config.TIMEOUT)
        status, hdrs, raw = r.status, r.headers, r.read(8192)
    except urllib.error.HTTPError as e:          # 3xx/4xx/5xx arrivano qui
        status, hdrs, raw = e.code, e.headers, e.read(4096)
    except Exception as e:                        # DNS, timeout, TLS…
        return {"error": str(e), "elapsed": time.perf_counter() - t0}
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in dict(hdrs).items()},
        "body_head": raw.decode("utf-8", "replace"),
        "elapsed": time.perf_counter() - t0,
    }


# --- PoC: il comando che RIPRODUCE il finding -------------------------------
def _shq(s):
    """Quota una stringa per la shell POSIX (single-quote safe)."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def make_session(cookie=None, token=None, header=None):
    """Costruisce un dict di header di SESSIONE dai flag CLI `--cookie`/`--token`/
    `--header`, da passare a `probe(..., session=...)` per testare la superficie
    autenticata. Pura, nessuna rete:
      - `cookie`  → `Cookie: <valore>` (la sessione del browser loggato);
      - `token`   → `Authorization: Bearer <valore>` (API a token);
      - `header`  → lista di stringhe `K: V` (header custom, es. `X-Api-Key: …`).
    Ritorna `None` se non c'è nulla (così il comportamento di default — nessun
    header di sessione — resta identico a prima). Gli header espliciti vincono
    sui collidenti, quindi un `--header 'Cookie: …'` esplicito sovrascrive
    `--cookie` (ultimo a parlare)."""
    s = {}
    if cookie:
        s["Cookie"] = cookie
    if token:
        s["Authorization"] = f"Bearer {token}"
    for raw in (header or []):
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        k = k.strip()
        if k:
            s[k] = v.strip()
    return s or None


def mask_session(session):
    """Maschera le credenziali di una sessione per il PoC (il materiale segreto
    non entra mai nel referto): il Bearer diventa `$TOKEN`, il Cookie `$COOKIE`;
    gli altri header di sessione (custom) restano verbatim perché non sono
    segreti d'autenticazione. Pura, nessuna rete. Ritorna un nuovo dict."""
    out = {}
    for k, v in (session or {}).items():
        kl = k.lower()
        if kl == "authorization":
            out[k] = "Bearer $TOKEN" if str(v).startswith("Bearer ") else "$TOKEN"
        elif kl == "cookie":
            out[k] = "$COOKIE"
        else:
            out[k] = v
    return out


def as_curl(url, method="GET", headers=None, body=None, timing=False, status_only=False, session=None):
    """Rende il `curl` equivalente a una probe → PoC copia-incolla. Costruito
    dalla STESSA tripla (url, headers, body) che la lane manda, così il comando
    non può divergere dalla richiesta reale. `timing` aggiunge il tempo totale
    (PoC time-based); `status_only` stampa solo lo status (PoC a loop).
    `session`: gli header di sessione, allegati come nella probe ma MASCHERATI
    (Bearer → $TOKEN, Cookie → $COOKIE) così il PoC riproduce la richiesta
    autenticata senza svelare la credenziale."""
    if status_only:
        out = ["curl", "-s", "-o", "/dev/null", "-w", _shq("%{http_code} ")]
    else:
        out = ["curl", "-i", "-sS"]
        if timing:
            out += ["-w", _shq("\\ntempo: %{time_total}s\\n")]
    if method and method.upper() != "GET":
        out += ["-X", method.upper()]
    # gli header di sessione (mascherati) sotto quelli espliciti della lane
    eff_headers = {**mask_session(session), **(headers or {})}
    for k, v in eff_headers.items():
        out += ["-H", _shq(f"{k}: {v}")]
    if body is not None:
        data = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        out += ["--data", _shq(data)]
    out.append(_shq(url))
    return " ".join(out)


# --- Tassonomia OWASP Top 10 2021 -------------------------------------------
# Etichetta di CATEGORIA (non un punteggio): mappa deterministica dal nome del
# `check` alla classe OWASP 2021. È un'etichetta tassonomica — NON un CVSS, che
# darebbe un numero finto (vedi dottrina). Serve a parlare la lingua standard
# dei referti/compliance senza inventare gravità. Le categorie OWASP si
# sovrappongono per natura: dove la scelta è un giudizio (jwt, race, mass-assign,
# cors, exposure) è commentata qui sotto e dichiarata come best-effort nel README.
OWASP_2021 = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery (SSRF)",
}

# Prefisso del `check` (la parte prima di ':') → codice categoria OWASP 2021.
# I check generici di tooling o puramente informativi (sast/secrets/nuclei/
# discover/fuzz/openapi) restano SENZA tag: il loro output è eterogeneo, dargli
# una sola categoria sarebbe disonesto.
_OWASP_BY_PREFIX = {
    # A01 — Broken Access Control: accesso/azione non autorizzati.
    "idor": "A01",            # id manomesso → risorsa altrui
    "cors": "A01",            # origine arbitraria legge risposte autenticate (CWE-942)
    "csrf": "A01",            # azione forgiata cross-site sulla sessione vittima (CWE-352)
    "mass-assign": "A01",     # il client imposta un campo server-controlled → escalation
    "redirect": "A01",        # open redirect (CWE-601)
    "traversal": "A01",       # path traversal / LFI → lettura di file fuori radice (CWE-22/98)
    "api-gate": "A01",        # endpoint che dovrebbe richiedere auth risponde aperto
    "auth-gate": "A01",       # idem lato area autenticata
    "exposure": "A01",        # file sensibile servito (CWE-200/538, mappato in A01 dal 2021)
    # A03 — Injection: input non neutralizzato interpretato come codice/query.
    "sqli": "A03", "sqli-time": "A03",
    "xss": "A03", "stored-xss": "A03", "dom-xss": "A03",
    "ssti": "A03", "nosqli": "A03",
    "crlf": "A03",            # CRLF / HTTP response splitting (header injection, CWE-113)
    # A04 — Insecure Design: difetto di logica (qui la race/TOCTOU, CWE-362).
    "race": "A04",
    # A05 — Security Misconfiguration: header/banner/cookie mal configurati.
    "header": "A05",          # security header mancante (header:hsts/csp/…)
    "security-headers": "A05", "server-banner": "A05",
    "cookie-flags": "A05", "cookie-samesite": "A05", "hsts-maxage": "A05",
    "csp-xss": "A05",         # CSP presente ma inerte contro l'XSS (unsafe-inline/no script-src)
    "xcto-nosniff": "A05",    # X-Content-Type-Options presente ma ≠ nosniff → MIME-sniffing attivo
    "xfo-clickjack": "A05",   # X-Frame-Options presente ma ≠ DENY/SAMEORIGIN (ALLOW-FROM deprecato) → framing non limitato
    "graphql": "A05",         # introspection / field-suggestion / batching / mutation-via-GET = misconfigurazione
    "xxe": "A05",             # XML External Entity: parser che risolve entità esterne (CWE-611, storicamente A04:2017-XXE → A05:2021)
    # A02 — Cryptographic Failures: debolezze del livello di trasporto (cert
    # scaduto/non valido, protocollo deprecato) → CWE-295/326/327.
    "tls": "A02",
    # A06 — Vulnerable and Outdated Components.
    "deps": "A06",
    # A07 — Identification and Authentication Failures: l'impatto delle debolezze
    # JWT (alg=none/chiave debole/exp ignorata) è la forgiatura del token →
    # bypass d'identità; il brute-force del login è la stessa classe.
    "auth": "A07", "jwt": "A07",
    # A10 — Server-Side Request Forgery.
    "ssrf": "A10",
}


def owasp_category(check):
    """Categoria OWASP Top 10 2021 per un `check`, come etichetta pronta per il
    referto (es. 'A03:2021 Injection'); '' se il check non ha una classe OWASP
    univoca (tooling generico/informativo). Deterministica e pura: dipende solo
    dal PREFISSO del check (la parte prima di ':', così 'sqli:username',
    'xss:q', 'exposure:/.env' ricadono sul loro prefisso). Nessuna rete."""
    prefix = str(check).split(":", 1)[0]
    code = _OWASP_BY_PREFIX.get(prefix)
    return OWASP_2021[code] if code else ""


# Prefisso del `check` → identificatori CWE (MITRE) della debolezza che la lane
# dimostra. È la stessa tassonomia che GitHub code scanning mostra sull'alert
# (via i tag `external/cwe/cwe-NNN` del SARIF), un fatto OGGETTIVO come la
# categoria OWASP — i numeri qui sotto sono quelli già documentati accanto alla
# mappa OWASP. ONESTÀ: una lane il cui output è ETEROGENEO (più debolezze
# distinte sotto lo stesso prefisso — `graphql`: introspection/CSRF/DoS; `deps`:
# una CWE diversa per ogni CVE) resta SENZA CWE univoca, esattamente come resta
# senza una sola categoria OWASP: assegnargliene una sarebbe disonesto.
_CWE_BY_PREFIX = {
    # A01 — Broken Access Control
    "idor": [639],            # Authorization Bypass Through User-Controlled Key
    "cors": [942],            # Permissive Cross-domain Policy with Untrusted Domains
    "csrf": [352],            # Cross-Site Request Forgery
    "mass-assign": [915],     # Improperly Controlled Modification of Object Attributes
    "redirect": [601],        # URL Redirection to Untrusted Site (open redirect)
    "traversal": [22, 98],    # Path Traversal; PHP Remote/Local File Inclusion
    "api-gate": [306],        # Missing Authentication for Critical Function
    "auth-gate": [306],
    "exposure": [200, 538],   # Exposure of Sensitive Information; File/Dir Info Exposure
    # A03 — Injection
    "sqli": [89], "sqli-time": [89],           # SQL Injection
    "xss": [79], "stored-xss": [79], "dom-xss": [79],  # Cross-site Scripting
    "ssti": [1336],           # Improper Neutralization in a Template Engine (SSTI)
    "nosqli": [943],          # Improper Neutralization in Data Query Logic (NoSQLi)
    "crlf": [113],            # HTTP Response Splitting (CRLF header injection)
    # A04 — Insecure Design
    "race": [362],            # Concurrent Execution using Shared Resource (race/TOCTOU)
    # A05 — Security Misconfiguration
    "header": [693], "security-headers": [693],  # Protection Mechanism Failure
    "server-banner": [200],   # Information Exposure (banner)
    "cookie-flags": [614, 1004],  # Sensitive Cookie Without Secure; Without HttpOnly
    "cookie-samesite": [1275],    # Sensitive Cookie with Improper SameSite Attribute
    "hsts-maxage": [319],     # Cleartext Transmission (HSTS disattivato → SSL strip)
    "csp-xss": [693],         # CSP presente ma inerte → meccanismo di protezione fallito
    "xcto-nosniff": [693],    # nosniff inerte → meccanismo di protezione fallito
    "xfo-clickjack": [1021],  # Improper Restriction of Rendered UI Layers (clickjacking)
    "xxe": [611],             # Improper Restriction of XML External Entity Reference (XXE)
    # A02 — Cryptographic Failures (transport)
    "tls": [295, 326, 327],   # Improper Cert Validation; Inadequate/Broken Crypto
    # A07 — Identification and Authentication Failures
    "auth": [307],            # Improper Restriction of Excessive Authentication Attempts
    "jwt": [347, 613],        # Improper Verification of Signature; Insufficient Session Expiration
    # A10 — Server-Side Request Forgery
    "ssrf": [918],
}


def cwe_ids(check):
    """Lista ORDINATA degli identificatori CWE (interi) della debolezza che il
    `check` dimostra; `[]` se il prefisso non ha una CWE univoca (tooling
    generico o lane a output eterogeneo come `graphql`/`deps`). Deterministica e
    pura, gemella di `owasp_category`: dipende solo dal PREFISSO del check
    (la parte prima di ':', così 'sqli:username' ricade su 'sqli'). Nessuna
    rete. Ritorna una NUOVA lista (il chiamante non muta la mappa interna)."""
    prefix = str(check).split(":", 1)[0]
    return sorted(_CWE_BY_PREFIX.get(prefix, ()))


# --- Finding: la forma unica di ogni risultato ------------------------------
def finding(check, target, verdict, severity, note="", evidence="", repro=""):
    # Il tag OWASP è derivato dal nome del check (deterministico): assegnato qui,
    # nel factory unico, così ogni lane — anche futura — lo porta senza doverlo
    # ricordare, e fluisce in JSON/testo/referto per costruzione.
    return {"check": check, "target": target, "verdict": verdict, "severity": severity,
            "note": note, "evidence": evidence, "repro": repro,
            "owasp": owasp_category(check)}


SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4, "ok": 5}
SEV_LABEL = {"crit": "CRIT", "high": "ALTO", "med": "MEDIO",
             "low": "BASSO", "info": "INFO", "ok": "ok"}


def gate(findings, threshold):
    """Findings con severità >= `threshold` (soglia inclusa, dal più grave).
    Deterministico, nessuna rete: è il cuore del gate di CI `scan --fail-on`.
    Una soglia più permissiva contiene sempre quella più severa
    (crit ⊆ high ⊆ med ⊆ low); una severità sconosciuta non scatta mai."""
    thr = SEV_ORDER.get(threshold, -1)
    return [f for f in findings if SEV_ORDER.get(f.get("severity"), 99) <= thr]


def gate_new(findings, threshold, new_fingerprints):
    """Findings NUOVI (fingerprint in `new_fingerprints`) con severità >= soglia.
    È il cuore del gate di REGRESSIONE `scan --fail-on-new`: scatta SOLO sui
    problemi comparsi dall'ultimo scan della sentinella, NON su tutto il debito
    preesistente (quello è il compito di `gate`, il gate assoluto). Così una
    pipeline può adottare ARIES senza fallire sul debito legacy e fermarsi solo
    sulle REGRESSIONI. Deterministico, nessuna rete: filtra l'uscita di `gate`
    (la soglia di severità, con la stessa monotonìa crit ⊆ high ⊆ med ⊆ low)
    tenendo i soli finding la cui fingerprint `check|target` è tra i nuovi.
    `new_fingerprints`: insieme di stringhe `check|target` come le produce
    `findings_db` (vuoto → non scatta mai, è il caso del primo scan/baseline)."""
    nf = set(new_fingerprints)
    return [f for f in gate(findings, threshold)
            if f"{f['check']}|{f['target']}" in nf]


def bench_green(lane_scores, selfchecks_ok):
    """Il benchmark è VERDE ⟺ ogni lane NON esente è a 2/2 (vero positivo +
    vero negativo) E tutti i self-check non-lane (referto, gate, samesite,
    owasp, avversariale) passano. È il cancello che fa uscire `aries bench` con
    codice ≠ 0 quando qualcosa regredisce, così un GitHub Action può bloccare un
    commit che rompe il tool. Deterministico, nessuna rete.
    - `lane_scores`: iterabile dei punteggi /2 delle lane NON esenti. La lane
      `dom-xss` è ESENTE (richiede Playwright, che in cloud/CI può mancare) → il
      chiamante NON la mette qui.
    - `selfchecks_ok`: bool, l'AND di tutti i self-check non-lane."""
    return all(s == 2 for s in lane_scores) and bool(selfchecks_ok)


def _summary(findings):
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    attn = sum(v for k, v in by.items() if k in ("crit", "high", "med", "low"))
    return {"total": len(findings), "attention": attn, "by_severity": by}


# --- output: testo (per gli umani) e JSON (per comporre lane / dare all'LLM) --
def to_json(title, findings):
    return json.dumps({"target": title, "findings": findings,
                       "summary": _summary(findings)},
                      ensure_ascii=False, indent=2)


def to_text(title, findings):
    rows = sorted(findings, key=lambda r: SEV_ORDER.get(r["severity"], 9))
    out = [f"\n=== ARIES — {title} ===", f"(controlli: {len(rows)})\n"]
    for r in rows:
        tag = SEV_LABEL.get(r["severity"], r["severity"])
        out.append(f"[{tag:5}] {r['check']}: {r['verdict']}")
        # Il tag OWASP si mostra sui soli finding "da guardare" (crit/high/med/low):
        # è lì che la tassonomia serve al triage/referto; sugli 'ok'/'info' sarebbe
        # rumore. In JSON invece ogni finding porta sempre 'owasp' (fedeltà macchina).
        if r.get("owasp") and r["severity"] in ("crit", "high", "med", "low"):
            out.append(f"         owasp: {r['owasp']}")
        if r.get("evidence"):
            out.append(f"         prova: {r['evidence']}")
        if r.get("note"):
            out.append(f"         nota : {r['note']}")
        if r.get("repro"):
            out.append(f"         repro: {r['repro']}")
    s = _summary(findings)
    info = s["by_severity"].get("info", 0)
    ok = s["total"] - s["attention"] - info
    out.append(f"\n-- da guardare: {s['attention']} · info/soppressi: {info} · ok: {ok} --")
    return "\n".join(out)
