"""Lane DEPS — orchestra trivy per le CVE note nelle TUE dipendenze.

Terzo "orchestra uno strumento vero, non reinventarlo" dopo gitleaks (segreti)
e semgrep (codice). Chiude la supply-chain: trivy legge i manifest delle
dipendenze (requirements.txt, package-lock.json, composer.lock, go.sum, ...) e
le incrocia col suo database di vulnerabilità note → le CVE che EREDITI dalle
librerie.

Difensivo, locale, sola lettura. Le CVE sono fatti oggettivi (versione X del
pacchetto Y ha la CVE Z) → poco rumore, al contrario della SAST euristica.
"""

import json
import os
import shutil
import subprocess
import tempfile

from core import finding

_SEV = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
        "LOW": "low", "UNKNOWN": "info"}


def run(path):
    if not shutil.which("trivy"):
        return [finding("deps", path, "ERRORE", "info", "trivy non installato", "")]
    if not os.path.exists(path):
        return [finding("deps", path, "ERRORE", "info", "percorso inesistente", path)]

    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    # NB: per le CVE NON escludiamo .venv/node_modules — i pacchetti INSTALLATI
    # sono la fonte giusta (copertura transitiva completa). Per la SAST sono
    # rumore, qui sono il bersaglio: le due lane hanno bisogni opposti.
    cmd = ["trivy", "fs", "--scanners", "vuln", "--quiet",
           "--format", "json", "--output", report, path]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        data = json.load(open(report)) if os.path.getsize(report) else {}
    except Exception as e:                       # noqa: BLE001
        return [finding("deps", path, "ERRORE", "info", "trivy fallito", str(e)[:140])]
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

    out = []
    for res in (data.get("Results") or []):
        target = res.get("Target", "")
        for v in (res.get("Vulnerabilities") or []):
            sev = _SEV.get(v.get("Severity", "UNKNOWN"), "info")
            pkg = v.get("PkgName", "?")
            ver = v.get("InstalledVersion", "?")
            fix = v.get("FixedVersion") or "nessun fix disponibile"
            out.append(finding(
                f"cve:{pkg}", f"{pkg}@{ver}", v.get("VulnerabilityID", "?"),
                sev, (v.get("Title") or "")[:110],
                f"fix → {fix}  ({target})"))
    if not out:
        return [finding("deps", path, "nessuna CVE", "ok",
                        "trivy non ha trovato vulnerabilità note nelle dipendenze",
                        path)]
    return out
