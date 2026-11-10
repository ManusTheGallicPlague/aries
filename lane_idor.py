"""Lane IDOR — broken access control: l'utente A riesce a leggere la risorsa di
B cambiando l'ID?

Serve modellare l'identità. Due modi:
  - header semplice (default `X-User`) — per setup/lab che la passano così;
  - `token` → `Authorization: Bearer <jwt>` — come il mondo vero (e Juice Shop).

E l'ID può stare in due posti:
  - query string: `.../doc?id=<n>`  (default, via `id_param`);
  - PATH: metti il placeholder `{id}` nell'URL, es. `.../rest/basket/{id}`.

Logica oggettiva (identica nei due casi):
  1. accedi alla TUA risorsa (baseline) → deve dare 200 (identità accettata)
  2. accedi alla risorsa di un ALTRO con la TUA identità
     - 200 coi dati altrui (corpo DIVERSO dal mio) → IDOR (nessun controllo di
       proprietà)
     - 200 ma STESSO corpo del mio → corpo costante (SPA 200-a-tutto / risorsa
       pubblica): NON sono dati per-utente → tacere (vedi guardia di contenuto)
     - 403/401 → ownership verificata (sicuro)

Guardia di CONTENUTO (anti-falso-positivo): lo status da solo non basta. Un
endpoint che risponde 200 a tutto (una SPA che serve sempre lo stesso guscio
HTML, una risorsa pubblica a corpo costante) darebbe owned=200 ∧ other=200 pur
non esponendo alcun dato per-utente — e il modello solo-status lo leggerebbe come
«risorsa altrui accessibile» (falso positivo). Un IDOR VERO espone i DATI
dell'altro: il corpo della risorsa altrui differisce dal mio. Perciò, a parità di
status 200, si afferma IDOR solo se i due corpi DIFFERISCONO; se sono identici si
tace (è l'unica lane offensiva differenziale che entra così nel banco
avversariale, puntata contro la trappola SPA 200-a-tutto).

ATTIVO: manda richieste → SOLO host in allowlist. Il token NON finisce nei
referti (evidenza = solo status + differenza di corpo, mai il corpo stesso).
"""

from urllib.parse import urlencode

from core import finding, probe, as_curl

# Sentinella: un id che NON corrisponde ad alcuna risorsa reale (12 cifre, scelta
# deterministica così il bench è riproducibile). La seconda guardia di contenuto
# (vedi `idor`) chiede a questo id INESISTENTE: una vera risorsa per-id lo respinge
# (404/403), un endpoint id-echo/aperto risponde 200 a qualunque id.
_NONCE_ID = "999999999999"


def _same_body(a, b):
    """True se i due corpi (`body_head`, troncati a 8 KB da core.probe) sono
    SOSTANZIALMENTE identici → l'endpoint serve un corpo costante, non dati
    per-utente. Confronto sul testo normalizzato (strip degli spazi ai bordi) per
    non inciampare in differenze di whitespace irrilevanti. Puro, nessuna rete.

    Distingue il corpo COSTANTE (SPA/risorsa pubblica) dal corpo per-utente. Il
    caso dell'endpoint che riflette SOLO l'id richiesto (corpi diversi per il solo
    valore iniettato, non per dati memorizzati) è chiuso dalla SECONDA guardia di
    contenuto in `idor` (la sonda nonce su un id inesistente), perché qui una
    normalizzazione dell'id rischierebbe falsi negativi (l'id compare spesso DENTRO
    i dati per-utente reali, es. "basket di user 1")."""
    return (a or "").strip() == (b or "").strip()


def _urls(base_url, id_param, owned, other):
    """Costruisce (url_owned, url_other, dove). Path mode se c'è `{id}`."""
    if "{id}" in base_url:
        return base_url.replace("{id}", str(owned)), base_url.replace("{id}", str(other)), "path"
    sep = "&" if "?" in base_url else "?"
    return (base_url + sep + urlencode({id_param: owned}),
            base_url + sep + urlencode({id_param: other}), id_param)


def idor(base_url, id_param="id", owned="1", other="2",
         identity_header="X-User", identity="1", token=None, method="GET"):
    if token:                                    # auth a token (Bearer): il mondo vero
        headers, ident = {"Authorization": f"Bearer {token}"}, "token Bearer"
        repro_headers = {"Authorization": "Bearer $TOKEN"}   # il JWT NON va nel referto
    elif identity_header and identity:           # identità via header semplice
        headers = repro_headers = {identity_header: identity}
        ident = f"'{identity}' ({identity_header})"
    else:
        headers = repro_headers = {}
        ident = "anonimo"

    url_own, url_oth, where = _urls(base_url, id_param, owned, other)
    r_own = probe(url_own, method, headers)
    r_oth = probe(url_oth, method, headers)

    if "error" in r_own or "error" in r_oth:
        return finding("idor", base_url, "ERRORE", "info", "probe fallita",
                       r_own.get("error") or r_oth.get("error"))
    so, st = r_own["status"], r_oth["status"]

    if so != 200:
        return finding("idor", base_url, "inconcludente", "info",
                       "la risorsa propria non dà 200: identità non accettata o setup errato",
                       f"owned({owned}) → HTTP {so} · identità {ident}")
    if st == 200:
        # Guardia di CONTENUTO: 200 su entrambe non basta. Un IDOR vero espone i
        # DATI dell'altro → corpo DIVERSO dal mio. Se i corpi sono identici, è un
        # endpoint a corpo costante (SPA 200-a-tutto / risorsa pubblica): non sono
        # dati per-utente → tacere (niente falso positivo).
        if _same_body(r_own.get("body_head"), r_oth.get("body_head")):
            return finding(f"idor:{where}", base_url, "controllo accesso ok", "ok",
                           f"la risorsa altrui ({other}) dà 200 ma con lo STESSO corpo della mia → corpo costante (SPA/pubblico), non dati per-utente: nessun IDOR",
                           f"owned({owned})=200 · other({other})=200 · corpi identici")
        # Seconda guardia di CONTENUTO (anti id-echo): i corpi differiscono, ma è
        # davvero un dato altrui o solo l'id richiesto riflesso nel guscio? Chiedo
        # la risorsa a un id INESISTENTE (sentinella). Una vera risorsa per-id
        # respinge l'id ignoto (non-200: 404/403) → il corpo DIVERSO di `other`
        # sono dati per-utente reali → IDOR attribuibile. Un endpoint id-echo (o
        # aperto a qualunque id: serve un guscio costante + l'id) risponde 200 anche
        # all'id inesistente → la differenza tra i corpi è il solo id riflesso, non
        # dati altrui memorizzati → tacere (nessun falso positivo). Un errore o un
        # non-200 sul nonce NON smaschera nulla → si conserva il verdetto VULNERABILE
        # (bias anti-falso-negativo: un errore transitorio non silenzia un IDOR reale).
        url_non, _, _ = _urls(base_url, id_param, _NONCE_ID, _NONCE_ID)
        r_non = probe(url_non, method, headers)
        if "error" not in r_non and r_non.get("status") == 200:
            return finding(f"idor:{where}", base_url, "controllo accesso ok", "ok",
                           f"un id INESISTENTE ({_NONCE_ID}) dà comunque 200 → l'endpoint risponde a QUALUNQUE id (id-echo/aperto), non è una risorsa per-id memorizzata: il corpo di {other} differisce solo per l'id riflesso, non sono dati altrui → nessun IDOR attribuibile",
                           f"owned({owned})=200 · other({other})=200 corpi diversi · nonce({_NONCE_ID})=200 (risponde a ogni id)")
        nonce_st = r_non.get("error") and "errore" or f"HTTP {r_non.get('status')}"
        return finding(f"idor:{where}", base_url, "VULNERABILE (IDOR)", "high",
                       f"con la mia identità ({ident}) accedo alla risorsa altrui ({other}) → broken access control",
                       f"owned({owned})=200 · other({other})=200 · corpi DIVERSI (dati per-utente) · nonce({_NONCE_ID})={nonce_st} (id ignoto respinto → store reale)",
                       as_curl(url_oth, method, repro_headers))
    return finding(f"idor:{where}", base_url, "controllo accesso ok", "ok",
                   f"la risorsa altrui ({other}) è negata (HTTP {st}) → proprietà verificata",
                   f"owned({owned})=200 · other({other})=HTTP {st}")


def run(base_url, id_param="id", owned="1", other="2",
        identity_header="X-User", identity="1", token=None):
    return [idor(base_url, id_param=id_param, owned=owned, other=other,
                 identity_header=identity_header, identity=identity, token=token)]
