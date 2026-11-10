"""Lane NUCLEI — orchestra nuclei: migliaia di template della community per
vulnerabilità note, misconfigurazioni, esposizioni e CVE sul web.

È il gemello OFFENSIVO di trivy: invece delle CVE nelle dipendenze, le falle
note raggiungibili via HTTP. Deterministico (template curati, poco rumore),
enorme copertura "già pronta".

ATTIVO: manda richieste al bersaglio → SOLO host in ALLOWLIST (lo verifichiamo
qui, prima di lanciare nuclei). Su bersagli tuoi o lab.
"""

import json
import shutil
import subprocess
from urllib.parse import urlparse

import config
from core import finding

_SEV = {"critical": "crit", "high": "high", "medium": "med",
        "low": "low", "info": "info", "unknown": "info"}


def run(url, severity="low,medium,high,critical", timeout=900):
    host = (urlparse(url).hostname or "").lower()
    if host not in config.ALLOWLIST:
        return [finding("nuclei", url, "RIFIUTATO", "info",
                        f"host '{host}' fuori ALLOWLIST (lane attiva: niente payload fuori confine)", "")]
    if not shutil.which("nuclei"):
        return [finding("nuclei", url, "ERRORE", "info", "nuclei non installato", "")]

    cmd = ["nuclei", "-u", url, "-jsonl", "-silent",
           "-disable-update-check", "-timeout", "10"]
    if severity:
        cmd += ["-severity", severity]            # di default salto 'info' puro (tech-detection)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:                         # noqa: BLE001
        return [finding("nuclei", url, "ERRORE", "info", "nuclei fallito", str(e)[:140])]

    out = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info") or {}
        sev = _SEV.get((info.get("severity") or "info").lower(), "info")
        tid = d.get("template-id") or d.get("templateID") or "?"
        at = d.get("matched-at") or d.get("matched_at") or d.get("host") or url
        out.append(finding(f"nuclei:{tid}", at, info.get("name") or tid, sev,
                           (info.get("description") or "").strip()[:110],
                           f"type={d.get('type', '?')}"))
    if not out:
        return [finding("nuclei", url, "nessun match", "ok",
                        "nuclei non ha trovato falle note con i template attuali", url)]
    return out
