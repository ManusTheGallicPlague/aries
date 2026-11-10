"""Lane SECRETS — orchestra gitleaks per trovare credenziali esposte nei TUOI repo.

È il primo esempio del principio "non reinventare lo scanner, orchestralo":
gitleaks ha già migliaia di regole per chiavi AWS, token GitHub, chiavi private,
ecc. ARIES lo lancia, normalizza i suoi risultati nel formato Finding, e li
compone con le altre lane.

Difensivo, locale, sola lettura. Usa --redact: il segreto NON finisce mai nel
referto (vedi solo che esiste, dove, e di che tipo).
"""

import json
import os
import shutil
import subprocess
import tempfile

from core import finding


def run(path, history=False):
    if not shutil.which("gitleaks"):
        return [finding("secrets", path, "ERRORE", "info",
                        "gitleaks non installato", "")]
    if not os.path.exists(path):
        return [finding("secrets", path, "ERRORE", "info", "percorso inesistente", path)]

    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd = ["gitleaks", "detect", "--source", path, "--redact",
           "--report-format", "json", "--report-path", report,
           "--no-banner", "--exit-code", "0"]
    if not history:
        cmd.append("--no-git")   # scansiona i file come sono, non la storia git
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        data = json.load(open(report)) if os.path.getsize(report) else []
    except Exception as e:                       # noqa: BLE001
        return [finding("secrets", path, "ERRORE", "info", "gitleaks fallito", str(e)[:140])]
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

    scope = "storia git" if history else "file"
    if not data:
        return [finding("secrets", path, "nessun segreto", "ok",
                        "gitleaks non ha trovato credenziali esposte",
                        f"scansione {scope} di {path}")]

    out = []
    for d in data:
        rule = d.get("RuleID") or "?"
        where = f"{d.get('File', '?')}:{d.get('StartLine', '?')}"
        out.append(finding(
            f"secret:{rule}", where, "SEGRETO ESPOSTO", "high",
            (d.get("Description") or "")[:100],
            f"match (redatto): {(d.get('Match') or '')[:80]}"))
    return out
