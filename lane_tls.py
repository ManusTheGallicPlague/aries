"""Lane TLS/transport — igiene del livello di trasporto (OWASP A02, dominio nuovo).

Domanda: il certificato TLS del bersaglio è valido (non scaduto, catena
verificabile) e la connessione negozia un protocollo moderno (≥ TLS 1.2)?
Un certificato SCADUTO fa rifiutare la connessione ai client (avviso di
sicurezza nel browser, servizio di fatto interrotto) ed è il sintomo tipico di
un rinnovo mancato; un protocollo deprecato (SSLv3 / TLS 1.0 / 1.1) espone a
downgrade e a cifrari ormai rotti.

Metodo — puro stdlib `ssl`/`socket`, due connessioni OGGETTIVE:
  1. VERIFICA PIENA (come un browser): `ssl.create_default_context()` con le CA
     di sistema (o un `cafile` per una CA interna/self-signed che FIDI). Se
     l'handshake fallisce con `X509_V_ERR_CERT_HAS_EXPIRED` (codice 10) → il
     certificato è scaduto; `...NOT_YET_VALID` (9) → non ancora valido. Se la
     verifica passa, leggiamo `notAfter` e segnaliamo se la scadenza è imminente.
  2. PROTOCOLLO: una connessione CERT_NONE (che completa SEMPRE l'handshake) per
     leggere la VERSIONE negoziata e il cifrario. < TLS 1.2 → finding.

La prova è OGGETTIVA: il verdetto di scadenza nasce dal codice di verifica di
OpenSSL (non da una stringa riflessa), quindi un endpoint che "somiglia" ma non
è davvero scaduto non può ingannarla — è la stessa logica della firma del
traversal o del prodotto calcolato dell'SSTI.

Confine: la lane apre socket DIRETTI (non passa da core.probe) → il confine
ALLOWLIST è imposto QUI, con la stessa regola di core.probe, così nessuna lane
lo aggira e nessun host esterno viene toccato.

Limiti onesti: la scadenza/validità della catena è il segnale oggettivo e
benchmarkato; l'enumerazione esaustiva dei cifrari deboli e del supporto di
OGNI versione di protocollo (che richiederebbe un handshake per versione, e il
set effettivo dipende dall'OpenSSL locale del client) è fuori scope —
riportiamo la versione NEGOZIATA, non tutte quelle accettate. La verifica usa le
CA di sistema (o un `--cafile` dichiarato); self-signed / CA sconosciuta /
hostname non corrispondente sono riportati come "catena non verificabile"
(reali, ma di classe diversa dalla scadenza).
"""

import socket
import ssl
import time
from urllib.parse import urlparse

import config
from core import finding, SEV_ORDER

# Versioni di protocollo deprecate (no PFS robusto, esposte a downgrade e a
# cifrari rotti): tutto ciò che sta sotto TLS 1.2 va disabilitato.
_DEPRECATED = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Giorni sotto i quali la scadenza è "imminente" (rinnovo da pianificare).
_NEAR_DAYS = 15
_TIMEOUT = 10


def _parse_target(target):
    """Da una stringa (`host`, `host:port`, o `https://host:port/...`) ricava
    (host, port). Default porta 443. Pura, nessuna rete."""
    t = str(target).strip()
    if "://" in t:
        u = urlparse(t)
        return (u.hostname or ""), (u.port or 443)
    # host:port semplice (no IPv6 fra parentesi, fuori scope del modello minimale)
    if t.count(":") == 1 and "[" not in t:
        h, _, p = t.partition(":")
        try:
            return h, int(p)
        except ValueError:
            return t, 443
    return t, 443


def _poc(host, port):
    """PoC: `s_client` è il modo canonico di ispezionare il certificato di un
    endpoint TLS (nessun segreto in gioco: il certificato del server è pubblico).
    Mostra le date di validità, soggetto ed emittente che motivano il verdetto."""
    return (f"echo | openssl s_client -connect {host}:{port} -servername {host} "
            f"2>/dev/null | openssl x509 -noout -dates -subject -issuer")


def _scope_ok(host):
    """Confine ALLOWLIST (stessa regola di core.probe): la lane apre socket
    diretti, quindi il controllo vive QUI e nessuna lane lo può aggirare."""
    return (host or "").lower() in config.ALLOWLIST


def _cert_check(host, port, cafile, timeout):
    """Connessione con VERIFICA PIENA della catena → finding `tls:cert`:
    scaduto / non-ancora-valido → VULNERABILE (high); altra verifica fallita →
    catena non verificabile (med); handshake ok → valido (ok) o in scadenza (med)."""
    tgt = f"{host}:{port}"
    ctx = ssl.create_default_context(cafile=cafile)   # cafile=None → CA di sistema
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert() or {}
                ver = s.version()
    except ssl.SSLCertVerificationError as e:
        code = getattr(e, "verify_code", None)
        msg = getattr(e, "verify_message", "") or str(e)
        if code == 10:   # X509_V_ERR_CERT_HAS_EXPIRED
            return finding(
                "tls:cert", tgt, "VULNERABILE (certificato scaduto)", "high",
                "il certificato TLS è SCADUTO → i client lo rifiutano (avviso di "
                "sicurezza, servizio di fatto interrotto); sintomo tipico di un "
                "rinnovo automatico mancato",
                f"verifica della catena fallita: {msg} (codice {code})",
                _poc(host, port))
        if code == 9:    # X509_V_ERR_CERT_NOT_YET_VALID
            return finding(
                "tls:cert", tgt, "VULNERABILE (certificato non ancora valido)", "high",
                "il certificato ha notBefore nel futuro → i client lo rifiutano "
                "(orologio del server sbagliato o emissione anticipata)",
                f"verifica della catena fallita: {msg} (codice {code})",
                _poc(host, port))
        # Altri motivi (self-signed, CA sconosciuta, hostname non corrispondente):
        # reali ma di CLASSE DIVERSA dalla scadenza → riportati onestamente, senza
        # la parola-chiave VULNERABILE, così il verdetto di scadenza resta netto.
        return finding(
            "tls:cert", tgt, "catena non verificabile", "med",
            "il certificato non supera la verifica standard della catena "
            "(self-signed, CA non fidata, o hostname non corrispondente): un "
            "client che verifica rifiuterebbe la connessione",
            f"verifica fallita: {msg}" + (f" (codice {code})" if code is not None else ""),
            _poc(host, port))
    except (socket.timeout, ssl.SSLError, OSError) as e:
        return finding(
            "tls:cert", tgt, "ERRORE", "info",
            "connessione TLS non riuscita (porta chiusa, non-TLS, o host "
            "irraggiungibile): nessun verdetto", str(e))
    # Handshake verificato OK → la catena è valida; quanto manca alla scadenza?
    not_after = cert.get("notAfter")
    try:
        secs = ssl.cert_time_to_seconds(not_after) if not_after else None
    except Exception:
        secs = None
    if secs is None:
        return finding(
            "tls:cert", tgt, "certificato valido", "ok",
            "la catena è verificata (scadenza non leggibile dal peer)",
            f"handshake {ver} ok, verifica catena superata")
    days = int((secs - time.time()) / 86400)
    if days < _NEAR_DAYS:
        return finding(
            "tls:cert", tgt, "certificato in scadenza", "med",
            f"il certificato è valido ma scade tra {days} giorni (< {_NEAR_DAYS}): "
            "pianificare il rinnovo per non interrompere il servizio",
            f"notAfter={not_after} (tra {days} giorni), handshake {ver} ok",
            _poc(host, port))
    return finding(
        "tls:cert", tgt, "certificato valido", "ok",
        f"catena verificata, scade tra {days} giorni",
        f"notAfter={not_after}, handshake {ver} ok")


def _protocol_check(host, port, timeout):
    """Connessione CERT_NONE (completa SEMPRE l'handshake, indipendente dalla
    verifica della catena) per leggere la VERSIONE di protocollo negoziata e il
    cifrario → finding `tls:protocol`. < TLS 1.2 → deprecato (med)."""
    tgt = f"{host}:{port}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          # prima di CERT_NONE (lo impone l'API)
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                ver = s.version()
                cipher = s.cipher()
    except (socket.timeout, ssl.SSLError, OSError) as e:
        return finding(
            "tls:protocol", tgt, "ERRORE", "info",
            "handshake TLS non riuscito per leggere la versione negoziata", str(e))
    cname = cipher[0] if cipher else "?"
    if ver in _DEPRECATED:
        return finding(
            "tls:protocol", tgt, f"VULNERABILE (protocollo deprecato: {ver})", "med",
            f"il server negozia {ver}, un protocollo deprecato (esposto a downgrade "
            "e cifrari rotti): disabilitare tutto ciò che sta sotto TLS 1.2",
            f"versione negoziata {ver}, cifrario {cname}",
            _poc(host, port))
    return finding(
        "tls:protocol", tgt, "protocollo moderno", "ok",
        f"il server negozia {ver} (≥ TLS 1.2)",
        f"versione negoziata {ver}, cifrario {cname}")


def tls_audit(target, cafile=None, timeout=_TIMEOUT):
    """Audit TLS/transport del bersaglio → [tls:cert, tls:protocol]. Confine
    ALLOWLIST imposto qui (socket diretti). `cafile`: bundle di CA fidate per
    verificare una CA interna/self-signed (default: CA di sistema)."""
    host, port = _parse_target(target)
    if not _scope_ok(host):
        return [finding(
            "tls:cert", str(target),
            f"host '{host}' fuori ALLOWLIST (rifiutato)", "info",
            "la lane TLS apre un socket diretto: il confine è imposto come in "
            "core.probe, nessun host esterno viene toccato")]
    return [_cert_check(host, port, cafile, timeout),
            _protocol_check(host, port, timeout)]


def _worst(findings):
    """Il finding PEGGIORE (per severità) dell'audit — riduce la lane a un
    verdetto unico per il benchmark, come lane_jwt._worst."""
    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))[0]


def run(target, cafile=None):
    return tls_audit(target, cafile=cafile)
