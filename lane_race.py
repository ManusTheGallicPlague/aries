"""Lane RACE — race condition / TOCTOU (modulo 09, parziale e ONESTO).

È l'UNICO pezzo di "logic flaw" che un tool può sfiorare in modo deterministico:
manda N richieste identiche CONCORRENTI a un'operazione che dovrebbe riuscire
UNA SOLA VOLTA (riscatta coupon, preleva, applica sconto) e conta quante
riescono. Se più di una riesce → race: il controllo "una volta" si aggira
correndo in parallelo.

GUARDIA anti-falso-positivo (post-burst): se >1 richiesta concorrente riesce, la
lane NON grida subito "race": prima manda una richiesta SEQUENZIALE post-burst.
Un'operazione *once-only* ha consumato la risorsa col burst → la sequenziale è
RIFIUTATA (non-2xx) → la race è attribuibile. Se invece riesce ancora (2xx),
l'endpoint è RIPETIBILE per natura (SPA 200-a-tutto, idempotente) → gli N successi
concorrenti non dimostrano un TOCTOU → la lane TACE. È la stessa logica di guardia
della D del CSRF / dell'esca del mass-assign, e porta la lane nel banco
avversariale (puntata su `/trap-spa`: 200-a-tutto → tace).

Confine onesto: questo SEGNALA un candidato (operazione state-changing che
riesce N volte in concorrenza E diventa non ripetibile dopo). Capire se è un vero
logic-flaw di business, e tutto il resto dei logic-flaw inediti, resta GIUDIZIO
umano/frontier. Il tool non lo decide. Limite della guardia: un'operazione
"una volta sola" la cui risorsa NON si esaurisce entro il burst (quota > N, o che
risponde 2xx idempotente anche dopo il consumo) sarebbe taciuta — scelta
conservativa verso l'anti-FP, dichiarata.

ATTIVO: manda richieste (concorrenti!) → SOLO host in allowlist.
"""

import concurrent.futures
import urllib.error
import urllib.request
from urllib.parse import urlparse

import config
from core import finding


def _fire(url, method, data, headers):
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:                            # noqa: BLE001
        return None


def race(url, method="POST", concurrency=20, body=None, headers=None, session=None):
    """`session` (dict di header: Cookie / Bearer / custom) è fusa negli header
    di OGNI richiesta concorrente → raggiunge un'operazione once-only DIETRO il
    login (riscatto/prelievo autenticato). La lane apre socket urllib diretti (non
    passa da core.probe), quindi il confine ALLOWLIST è imposto QUI, come sempre;
    la sessione aggiunge credenziali verso lo STESSO host autorizzato, non ne
    raggiunge di nuovi. Nessun PoC `curl` da mascherare (l'evidenza è un conteggio
    di successi, non una richiesta riprodotta)."""
    host = (urlparse(url).hostname or "").lower()
    if host not in config.ALLOWLIST:
        return finding("race", url, "RIFIUTATO", "info",
                       f"host '{host}' fuori ALLOWLIST (lane attiva)", "")
    headers = {**(session or {}), **(headers or {})}  # gli header espliciti vincono sul collide
    data = body.encode() if isinstance(body, str) else body
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(_fire, url, method, data, headers) for _ in range(concurrency)]
        statuses = [f.result() for f in futures]

    ok = sum(1 for s in statuses if s is not None and 200 <= s < 300)
    if ok <= 1:
        return finding("race", url, "nessuna race rilevata", "ok",
                       "le richieste concorrenti sono state serializzate (max 1 successo)",
                       f"successi 2xx: {ok} su {concurrency}")

    # ok > 1: potrebbe essere una VERA race (il controllo "una volta sola" si aggira
    # in parallelo) OPPURE un endpoint RIPETIBILE per natura — una SPA 200-a-tutto,
    # un'operazione idempotente — che "riesce" N volte per costruzione, non per un
    # TOCTOU. GUARDIA anti-falso-positivo (come la D del CSRF / l'esca del
    # mass-assign): dopo il burst, un'operazione once-only ha CONSUMATO la risorsa,
    # quindi una richiesta SEQUENZIALE post-burst dev'essere RIFIUTATA (non-2xx:
    # 409/403/410…). Se invece riesce ANCORA (2xx), l'operazione non è "una volta
    # sola" → gli N successi concorrenti non dimostrano una race → la lane TACE.
    post = _fire(url, method, data, headers)
    repeatable = post is not None and 200 <= post < 300
    if repeatable:
        return finding("race", url, "operazione ripetibile (nessuna race attribuibile)", "ok",
                       f"{ok}/{concurrency} richieste concorrenti sono riuscite, MA una "
                       f"richiesta SEQUENZIALE post-burst riesce ancora (HTTP {post}): "
                       "l'operazione NON è 'una volta sola' (ripetibile/idempotente/200-a-tutto) "
                       "→ gli N successi concorrenti non dimostrano un TOCTOU",
                       f"successi 2xx: {ok} su {concurrency}; sequenziale post-burst: HTTP {post}")
    return finding("race", url, "VULNERABILE (race condition)", "high",
                   f"{ok}/{concurrency} richieste concorrenti sono riuscite E la richiesta "
                   f"sequenziale post-burst è RIFIUTATA (HTTP {post}): l'operazione è "
                   "'una volta sola' fuori concorrenza, ma il controllo si aggira correndo "
                   "in parallelo (TOCTOU)",
                   f"successi 2xx: {ok} su {concurrency}; sequenziale post-burst rifiutato: HTTP {post}")


def run(url, method="POST", concurrency=20, body=None, session=None):
    return [race(url, method=method, concurrency=concurrency, body=body, session=session)]
