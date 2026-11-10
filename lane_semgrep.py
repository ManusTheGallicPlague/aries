"""Lane SAST — orchestra semgrep: trova CLASSI di vulnerabilità nel TUO codice.

È il gemello potente di gitleaks: gitleaks cerca segreti, semgrep cerca pattern
di codice vulnerabile (SQLi, injection, eval, deserializzazione, path traversal,
shell=True, ...). Automatizza il tipo di analisi che su Nexus ho fatto a mano.

Difensivo, locale, sola lettura. Il codice NON lascia la macchina: semgrep
scarica solo le regole (pubbliche) dal registro e le cache in ~/.semgrep.
"""

import json
import os
import shutil
import subprocess

from core import finding

# semgrep: ERROR = grave, WARNING = medio, INFO = basso → severità ARIES
_SEV = {"ERROR": "high", "WARNING": "med", "INFO": "low"}

# Su repo veri: ignora il codice di TERZI e gli artefatti (sennò annega nel rumore).
_EXCLUDE = [".venv", "venv", "node_modules", "__pycache__", "vendor",
            "dist", "build", ".git", ".ruff_cache", ".pytest_cache", "migrations"]


def _likely_fp(cid, evidence):
    """Triage del rumore: euristiche ESPLICITE di falso positivo, col motivo.
    Non nascondiamo il finding (nasconderne uno vero sarebbe peggio) — lo
    declassiamo a 'info', così il segnale reale sale in cima ma resta visibile
    cosa è stato soppresso e perché. Imparate sul giro reale di Nexus."""
    ev = evidence or ""
    if cid == "unquoted-attribute-var" and ("{{ '" in ev or '{{ "' in ev):
        return "emette una keyword statica (es. 'selected'/'checked'), non input utente"
    if cid == "var-in-script-tag" and "tojson" in ev:
        return "usa |tojson, il modo sicuro per passare dati a uno <script>"
    if cid == "dynamic-urllib-use-detected" and ('urlopen("http' in ev or "urlopen('http" in ev):
        return "URL letterale, non un valore dinamico"
    return None


def _source_line(path, line):
    """La riga di codice vera dal file. semgrep nasconde lo snippet agli utenti
    anonimi ('requires login'), ma noi abbiamo file:riga → la prova ce la
    prendiamo da soli (ground truth)."""
    try:
        if isinstance(line, int) and path and os.path.isfile(path):
            with open(path, "r", errors="replace") as f:
                return f.readlines()[line - 1].strip()[:90]
    except Exception:                            # noqa: BLE001
        pass
    return ""


def run(path, config="p/security-audit"):
    if not shutil.which("semgrep"):
        return [finding("sast", path, "ERRORE", "info", "semgrep non installato", "")]
    if not os.path.exists(path):
        return [finding("sast", path, "ERRORE", "info", "percorso inesistente", path)]

    cmd = ["semgrep", "--config", config, "--json", "--quiet",
           "--metrics", "off", "--disable-version-check"]
    for e in _EXCLUDE:
        cmd += ["--exclude", e]
    cmd.append(path)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        data = json.loads(p.stdout) if p.stdout.strip() else {"results": []}
    except Exception as e:                       # noqa: BLE001
        return [finding("sast", path, "ERRORE", "info", "semgrep fallito", str(e)[:140])]

    results = data.get("results", [])
    if not results:
        return [finding("sast", path, "nessun problema", "ok",
                        "semgrep non ha trovato pattern vulnerabili",
                        f"config={config} · {path}")]

    out = []
    for r in results:
        cid = (r.get("check_id") or "?").split(".")[-1]       # ultima parte dell'id, leggibile
        extra = r.get("extra") or {}
        line = (r.get("start") or {}).get("line", "?")
        sev = _SEV.get(extra.get("severity", ""), "med")
        msg = (extra.get("message") or "")[:120]
        rpath = r.get("path", path)
        snippet = _source_line(rpath, line)
        if not snippet:                          # fallback se il file non è leggibile
            snippet = (extra.get("lines") or "").strip().replace("\n", " ")[:80]
        fp = _likely_fp(cid, snippet)
        if fp:                                   # declassato, non nascosto
            out.append(finding(f"sast:{cid}", f"{rpath}:{line}",
                               "probabile falso positivo", "info",
                               f"{fp} (semgrep: {cid})", snippet))
        else:
            out.append(finding(f"sast:{cid}", f"{rpath}:{line}",
                               "VULNERABILITÀ", sev, msg, snippet))
    return out
