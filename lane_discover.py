"""Lane DISCOVER (recon, modulo 01) — scopre endpoint/directory nascosti con ffuf.

Trova la SUPERFICIE d'attacco invece di fartela dire nei PROFILES: prova una
wordlist di percorsi comuni/sensibili e riporta quelli che esistono. Alimenta le
lane d'attacco (scopri → poi attacchi).

ATTIVO: manda richieste → SOLO host in ALLOWLIST. `-ac` auto-calibra sulla
risposta "not found" → gestisce anche le SPA che rispondono 200 a tutto.
"""

import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

import config
from core import finding

_WL = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")

# Percorsi la cui semplice ESISTENZA è già notevole (non solo "c'è una rotta").
# Incluse le directory che SERVONO file scaricabili (ftp/logs/backup): su Juice
# Shop /ftp e /support/logs erano degradati a 'info' perché mancavano qui.
_SENSITIVE = (".git", ".env", ".svn", ".htpasswd", ".htaccess", "id_rsa", ".ssh",
              "credential", "secret", "backup", "dump", ".sql", "server-status",
              ".aws", "encryptionkey", "web.config", "appsettings", ".ds_store",
              "phpinfo", "actuator", "key", "token", "ftp", "logs")


def _sev(path):
    p = path.lower()
    return "med" if any(s in p for s in _SENSITIVE) else "info"


def run(base_url, wordlist=None):
    host = (urlparse(base_url).hostname or "").lower()
    if host not in config.ALLOWLIST:
        return [finding("discover", base_url, "RIFIUTATO", "info",
                        f"host '{host}' fuori ALLOWLIST (lane attiva)", "")]
    if not shutil.which("ffuf"):
        return [finding("discover", base_url, "ERRORE", "info", "ffuf non installato", "")]
    wl = wordlist or _WL
    if not os.path.isfile(wl):
        return [finding("discover", base_url, "ERRORE", "info", "wordlist mancante", wl)]

    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    target = base_url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", target, "-w", wl, "-ac", "-s",
           "-t", "40", "-timeout", "10", "-of", "json", "-o", report]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        data = json.load(open(report)) if os.path.getsize(report) else {}
    except Exception as e:                       # noqa: BLE001
        return [finding("discover", base_url, "ERRORE", "info", "ffuf fallito", str(e)[:140])]
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

    results = data.get("results") or []
    if not results:
        return [finding("discover", base_url, "niente di nascosto", "ok",
                        "ffuf non ha trovato endpoint oltre la baseline",
                        f"wordlist {os.path.basename(wl)}")]
    out = []
    for r in results:
        url = r.get("url") or (base_url.rstrip("/") + "/" + (r.get("input", {}).get("FUZZ", "")))
        path = urlparse(url).path
        st = r.get("status", "?")
        out.append(finding(
            f"discover:{path}", url, f"endpoint trovato (HTTP {st})", _sev(path),
            "superficie scoperta — da passare alle altre lane",
            f"HTTP {st} · {r.get('length', '?')}b"))
    return out
