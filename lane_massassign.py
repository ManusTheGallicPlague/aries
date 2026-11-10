"""Lane MASS-ASSIGN — rileva il mass assignment (autobinding / object injection).

Domanda: un endpoint di scrittura che aggiorna/crea una risorsa lega al modello
TUTTI i campi del corpo, lasciando al client impostare campi che dovrebbero
essere SERVER-controlled (es. `role`, `isAdmin`, `verified`, `balance`)?

Prova differenziale OGGETTIVA su due richieste (come lo stored-XSS):
  1. SCRITTURA — invio i campi legittimi + un campo PRIVILEGIATO (`--field`,
     es. `role`) con un valore-nonce unico + un campo-ESCA dal nome inventato
     (che NESSUN modello reale possiede) con un altro nonce.
  2. LETTURA  — leggo lo stato (un endpoint GET dedicato, oppure il corpo della
     risposta di scrittura) e cerco i due nonce.

Tre esiti:
  - il nonce PRIVILEGIATO riemerge E quello-esca NO → il server ha legato un
    campo REALE del modello ma scartato l'esca → MASS ASSIGNMENT (ALTO).
  - entrambi i nonce riemergono                      → l'endpoint RIFLETTE tutto
    (eco indiscriminato): non si distingue il binding dall'eco verbatim del
    corpo → la lane TACE (guardia anti falso positivo, come la D del CSRF).
  - il nonce privilegiato NON riemerge               → il campo è stato scartato
    (whitelist server-side) → ok.

Il campo-esca è la guardia: separa il binding SELETTIVO a un modello (accetta la
colonna reale `role`, scarta l'esca inesistente) dall'eco verbatim del corpo
(che riflette pure l'esca). Il nonce casuale garantisce che il match sia proprio
ciò che abbiamo appena scritto, non un residuo di una scrittura precedente.

Limite onesto: inietta un valore-NONCE nel campo privilegiato; se il server
VALIDA il valore del campo (enum, es. `role ∈ {user,admin}`) il nonce viene
scartato → falso negativo (si usa `--value admin` per mirare un valore accettato).
Un endpoint schema-less che accetta QUALSIASI chiave riflette anche l'esca → la
lane tace (non si distingue dal mero eco). ATTIVO: manda richieste di scrittura,
SOLO host in ALLOWLIST (via core.probe).
"""

import json as _json
import secrets as _secrets
from urllib.parse import urlencode

from core import finding, probe, as_curl


def _build(legit, extra, send_as):
    """Corpo + Content-Type: i campi legittimi + quelli iniettati (privilegiato
    ed esca). Un solo posto così la richiesta e il PoC non possono divergere."""
    fields = dict(legit or {})
    fields.update(extra)
    if send_as == "json":
        return _json.dumps(fields), "application/json"
    return urlencode(fields), "application/x-www-form-urlencoded"


def mass_assign(write_url, read_url=None, field="role", value=None,
                legit=None, send_as="json", cookie=None):
    """Scrive su `write_url` un campo privilegiato + un campo-esca e verifica,
    rileggendo lo stato (`read_url` o il corpo della risposta), quale dei due
    sopravvive. Ritorna un Finding. Il PoC riproduce la richiesta di scrittura."""
    nonce = _secrets.token_hex(4)
    inj = value if value else "arzma" + nonce          # valore nel campo privilegiato
    ctl_field = "aries_ctl_" + nonce                   # campo-ESCA: nessun modello reale lo ha
    ctl = "arzct" + nonce
    body, ctype = _build(legit, {field: inj, ctl_field: ctl}, send_as)
    wh = {"Content-Type": ctype}
    if cookie:
        wh["Cookie"] = cookie
    w = probe(write_url, "POST", wh, body)
    if "error" in w:
        return finding(f"mass-assign:{field}", write_url, "ERRORE", "info",
                       "probe di SCRITTURA fallita", w["error"])

    # materiale di lettura: un endpoint GET dedicato, o il corpo della risposta
    if read_url:
        rh = {"Cookie": cookie} if cookie else None
        r = probe(read_url, "GET", rh)
        if "error" in r:
            return finding(f"mass-assign:{field}", read_url, "ERRORE", "info",
                           "probe di LETTURA fallita", r["error"])
        read_body, where, rstat = r.get("body_head", ""), read_url, r.get("status")
    else:
        read_body = w.get("body_head", "")
        where, rstat = write_url + " (corpo risposta)", w.get("status")

    bound = inj in read_body                            # il campo privilegiato è sopravvissuto
    echoed = ctl in read_body                           # ...e anche l'esca? (allora è eco)
    base_ev = f"scrittura HTTP {w.get('status')}, lettura HTTP {rstat}"

    # PoC: la stessa richiesta di scrittura che inietta il campo privilegiato,
    # col Cookie mascherato ($COOKIE) — la sessione non entra nel referto.
    poc_h = {"Content-Type": ctype}
    if cookie:
        poc_h["Cookie"] = "$COOKIE"
    poc = as_curl(write_url, "POST", poc_h, body)

    if bound and not echoed:
        return finding(
            f"mass-assign:{field}", write_url, "VULNERABILE (mass assignment)", "high",
            f"il campo privilegiato '{field}' impostato dal client è stato LEGATO al "
            f"modello e persiste nella lettura, mentre il campo-esca inesistente è stato "
            f"scartato → binding selettivo a una colonna reale che il client non dovrebbe "
            f"controllare (escalation: ruolo/privilegi/flag server-side)",
            f"'{field}={inj}' presente in {where}, esca '{ctl_field}' assente ({base_ev})",
            poc)
    if bound and echoed:
        return finding(
            f"mass-assign:{field}", write_url, "non rilevata (eco indiscriminato)", "ok",
            "la lettura riflette ANCHE il campo-esca inesistente → l'endpoint fa l'eco del "
            "corpo, non un binding selettivo a un modello: il mass assignment non è "
            "dimostrabile qui (guardia anti falso positivo)",
            f"sia '{field}={inj}' sia l'esca '{ctl_field}={ctl}' presenti in {where} ({base_ev})")
    return finding(
        f"mass-assign:{field}", write_url, "non rilevata (campo scartato)", "ok",
        f"il campo privilegiato '{field}' impostato dal client NON riemerge nella lettura "
        f"→ scartato/non legato al modello (whitelist server-side)",
        f"'{field}={inj}' assente in {where} ({base_ev})")


def run(write_url, read_url=None, field="role", value=None, legit=None,
        send_as="json", cookie=None):
    return [mass_assign(write_url, read_url=read_url, field=field, value=value,
                        legit=legit, send_as=send_as, cookie=cookie)]
