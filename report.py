"""ARIES — export dei findings in un referto condivisibile (Markdown / HTML).

Principio invariato: i FATTI restano quelli prodotti dalle lane (core.finding).
Questo modulo è solo *presentazione* — non inventa verdetti, non tocca le
severità, non aggiunge interpretazione. Prende la stessa lista di Finding che
il motore stampa a schermo e la rende in un documento leggibile, **con il PoC
`curl` dentro** (il campo `repro`, già mascherato con `$TOKEN` dalle lane).

Puro Python, stdlib. I findings sono raggruppati per severità (dal più grave),
così il referto si legge dall'alto come una lista di priorità.
"""

import html
import time

import core

# Estensioni → formato. Ambiguo/sconosciuto → Markdown (il default sicuro).
_MD_EXT = (".md", ".markdown")
_HTML_EXT = (".html", ".htm")


def _groups(findings):
    """Raggruppa per severità nell'ordine di gravità di core.SEV_ORDER.
    Ritorna una lista di (severity, label, [findings]) senza i gruppi vuoti."""
    buckets = {}
    for f in findings:
        buckets.setdefault(f["severity"], []).append(f)
    out = []
    for sev in sorted(buckets, key=lambda s: core.SEV_ORDER.get(s, 9)):
        out.append((sev, core.SEV_LABEL.get(sev, sev), buckets[sev]))
    return out


def _counts_line(findings):
    """La stessa aritmetica di core.to_text: da guardare / info / ok."""
    s = core._summary(findings)
    info = s["by_severity"].get("info", 0)
    ok = s["total"] - s["attention"] - info
    return s["total"], s["attention"], info, ok


# --- Markdown ----------------------------------------------------------------
def to_markdown(title, findings, sentinella=None, now=None):
    total, attn, info, ok = _counts_line(findings)
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    out = [f"# ARIES — referto: {title}", "",
           f"_Generato: {ts}_", "",
           f"**Riepilogo:** {total} controlli · "
           f"da guardare: {attn} · info: {info} · ok: {ok}", ""]
    for sev, label, fs in _groups(findings):
        out.append(f"## {label} ({len(fs)})")
        out.append("")
        for f in fs:
            out.append(f"### `{f['check']}` — {f['target']}")
            out.append(f"- **verdetto:** {f['verdict']}")
            if f.get("owasp"):
                out.append(f"- **OWASP:** {f['owasp']}")
            if f.get("evidence"):
                out.append(f"- **prova:** {f['evidence']}")
            if f.get("note"):
                out.append(f"- **nota:** {f['note']}")
            if f.get("repro"):
                out.append("")
                out.append("PoC (riproduce il finding):")
                out.append("")
                out.append("```sh")
                out.append(f["repro"])
                out.append("```")
            out.append("")
    if sentinella and not sentinella.get("first"):
        out.append("## Sentinella (confronto con lo scan precedente)")
        out.append("")
        out.append(f"- 🆕 nuovi: {len(sentinella.get('new', []))}")
        for x in sentinella.get("new", []):
            out.append(f"  - `{x}`")
        out.append(f"- ✅ risolti: {len(sentinella.get('fixed', []))}")
        for x in sentinella.get("fixed", []):
            out.append(f"  - `{x}`")
        out.append(f"- = invariati: {len(sentinella.get('persistent', []))}")
        out.append("")
    out.append("---")
    out.append("")
    out.append("_ARIES — security testing locale, deterministico e onesto. "
               "I fatti li produce il codice; questo referto è solo presentazione._")
    return "\n".join(out) + "\n"


# --- HTML (autoconsistente, nessuna dipendenza esterna) ----------------------
# Colori per severità: solo CSS inline, niente CDN, niente JS.
_SEV_COLOR = {"crit": "#b00020", "high": "#d35400", "med": "#b8860b",
              "low": "#2a6f97", "info": "#555", "ok": "#2e7d32"}

_HTML_CSS = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, system-ui, sans-serif; max-width: 920px;
       margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
h1 { border-bottom: 2px solid currentColor; padding-bottom: .3rem; }
.meta { color: #777; font-size: .9rem; }
.sev { display: inline-block; color: #fff; padding: .05rem .5rem;
       border-radius: .3rem; font-size: .85rem; font-weight: 700; }
.finding { border: 1px solid #8884; border-left-width: 5px; border-radius: .4rem;
           padding: .6rem .9rem; margin: .7rem 0; }
.finding h3 { margin: .1rem 0 .4rem; font-size: 1.05rem; }
.kv { margin: .15rem 0; }
.kv b { color: #666; }
pre { background: #2b2b2b; color: #eee; padding: .7rem; border-radius: .4rem;
      overflow-x: auto; font-size: .85rem; }
code { font-family: ui-monospace, Menlo, Consolas, monospace; }
footer { margin-top: 2rem; color: #777; font-size: .85rem;
         border-top: 1px solid #8884; padding-top: .7rem; }
"""


def _h(s):
    return html.escape(str(s))


def to_html(title, findings, sentinella=None, now=None):
    total, attn, info, ok = _counts_line(findings)
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    parts = ["<!doctype html>", '<html lang="it"><head>',
             '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             f"<title>ARIES — referto: {_h(title)}</title>",
             f"<style>{_HTML_CSS}</style></head><body>",
             f"<h1>ARIES — referto: {_h(title)}</h1>",
             f'<p class="meta">Generato: {_h(ts)} · {total} controlli · '
             f"da guardare: {attn} · info: {info} · ok: {ok}</p>"]
    for sev, label, fs in _groups(findings):
        color = _SEV_COLOR.get(sev, "#555")
        parts.append(f"<h2>{_h(label)} <span class=\"meta\">({len(fs)})</span></h2>")
        for f in fs:
            parts.append(f'<div class="finding" style="border-left-color:{color}">')
            parts.append(f'<h3><span class="sev" style="background:{color}">'
                         f"{_h(label)}</span> <code>{_h(f['check'])}</code> — "
                         f"{_h(f['target'])}</h3>")
            parts.append(f'<div class="kv"><b>verdetto:</b> {_h(f["verdict"])}</div>')
            if f.get("owasp"):
                parts.append(f'<div class="kv"><b>OWASP:</b> {_h(f["owasp"])}</div>')
            if f.get("evidence"):
                parts.append(f'<div class="kv"><b>prova:</b> {_h(f["evidence"])}</div>')
            if f.get("note"):
                parts.append(f'<div class="kv"><b>nota:</b> {_h(f["note"])}</div>')
            if f.get("repro"):
                parts.append("<div class=\"kv\"><b>PoC (riproduce il finding):</b></div>")
                parts.append(f"<pre><code>{_h(f['repro'])}</code></pre>")
            parts.append("</div>")
    if sentinella and not sentinella.get("first"):
        parts.append("<h2>Sentinella (confronto con lo scan precedente)</h2><ul>")
        parts.append(f"<li>🆕 nuovi: {len(sentinella.get('new', []))}</li>")
        parts.append(f"<li>✅ risolti: {len(sentinella.get('fixed', []))}</li>")
        parts.append(f"<li>= invariati: {len(sentinella.get('persistent', []))}</li>")
        parts.append("</ul>")
    parts.append("<footer>ARIES — security testing locale, deterministico e "
                 "onesto. I fatti li produce il codice; questo referto è solo "
                 "presentazione.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


# --- Dashboard ANDAMENTO NEL TEMPO (read-only, dalla findings-DB) -------------
# Presentazione pura: NON inventa nulla, rende la `timeline` (già calcolata da
# findings_db.timeline, funzione pura) in Markdown/HTML. Due viste: la serie
# degli scan (quando, quanti problemi, nuovi/risolti) e i problemi aperti con la
# loro ETÀ (da quando sono aperti, in quanti scan).
def _age_label(rec):
    """Testo onesto sull'anzianità di un problema: aperto da quando / risolto."""
    if rec["open"]:
        return f"aperto dal {rec['first_seen']} · visto in {rec['occurrences']} scan"
    return f"risolto · ultimo avvistamento {rec['last_seen']} ({rec['occurrences']} scan)"


# --- Sparkline SVG (andamento grafico dei problemi, inline, senza JS/CDN) ------
# La tabella «Serie degli scan» dà i numeri; una sparkline li rende leggibili a
# colpo d'occhio (il debito sale o scende?). Geometria PURA: dai conteggi «da
# guardare» per scan deriva i punti (x,y) della polyline → deterministica e
# testabile SENZA render (il self-check asserisce sulla geometria, non sul testo
# SVG). Come il resto del referto: solo presentazione, nessun fatto inventato.
_SPARK_W = 680      # larghezza area di disegno (px, coordinate del viewBox)
_SPARK_H = 90       # altezza area di disegno (px)
_SPARK_PAD = 10     # margine interno (px), così punti e linea non toccano i bordi


def sparkline_points(counts, w=_SPARK_W, h=_SPARK_H, pad=_SPARK_PAD):
    """Dalla lista dei conteggi «da guardare» (interi ≥0, uno per scan, nell'ordine
    temporale) ai punti (x,y) della polyline SVG. **PURA**: nessun render, nessun
    I/O → deterministica e testabile da sola. Convenzioni:
      - x spaziati UNIFORMEMENTE da `pad` a `w-pad` (primo scan a sinistra, ultimo
        a destra); un solo punto → centrato (nessuna divisione per zero);
      - y INVERTITO (lo 0 dell'SVG è in alto): un conteggio più ALTO sta più in
        ALTO sullo schermo (y più PICCOLA) — l'intuizione «la linea sale = più
        problemi». Scala sul MASSIMO della serie; se il massimo è 0 (nessun
        problema mai) la linea è piatta sulla BASE (y = h-pad), non a metà;
      - lista vuota → nessun punto (`[]`).
    Ritorna una lista di tuple (x, y) arrotondate a 2 decimali (output stabile)."""
    n = len(counts)
    if n == 0:
        return []
    lo, hi = pad, w - pad
    if n == 1:
        xs = [(lo + hi) / 2]
    else:
        step = (hi - lo) / (n - 1)
        xs = [lo + i * step for i in range(n)]
    top, base = pad, h - pad
    mx = max(counts)
    pts = []
    for x, c in zip(xs, counts):
        y = base if mx == 0 else base - (c / mx) * (base - top)
        pts.append((round(x, 2), round(y, 2)))
    return pts


def _sparkline_svg(scan_rows, w=_SPARK_W, h=_SPARK_H, pad=_SPARK_PAD):
    """Rende la sparkline dei problemi «da guardare» per scan in un `<svg>` inline
    (niente JS, niente CDN, niente immagini esterne). Ritorna '' con MENO di 2
    scan: una linea di tendenza ha bisogno di almeno due punti, e con 0/1 scan
    non c'è un ANDAMENTO da mostrare (la tabella basta)."""
    counts = [sc["attention"] for sc in scan_rows]
    if len(counts) < 2:
        return ""
    pts = sparkline_points(counts, w, h, pad)
    poly = " ".join(f"{x},{y}" for x, y in pts)
    dots = "".join(f'<circle cx="{x}" cy="{y}" r="2.5" fill="#b00020"/>'
                   for x, y in pts)
    mx = max(counts)
    base = h - pad
    return (
        f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" '
        f'role="img" aria-label="andamento dei problemi da guardare per scan, '
        f'dal primo (sinistra) all\'ultimo (destra); massimo {mx}" '
        f'style="max-width:{w}px;border:1px solid #8884;border-radius:.4rem;'
        f'margin:.6rem 0;background:#8881">'
        f'<line x1="{pad}" y1="{base}" x2="{w - pad}" y2="{base}" '
        f'stroke="#8886" stroke-width="1"/>'
        f'<polyline points="{poly}" fill="none" stroke="#b00020" '
        f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
        f'{dots}'
        f'<text x="{pad}" y="{pad + 9}" font-size="11" fill="#777">'
        f'max {mx} da guardare</text>'
        f'</svg>'
    )


def timeline_markdown(target, tl, now=None):
    s = tl["summary"]
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    out = [f"# ARIES — andamento: {target}", "",
           f"_Generato: {ts}_", "",
           f"**Riepilogo:** {s['scans']} scan · problemi aperti: {s['open']} · "
           f"risolti: {s['resolved']} · mai visti: {s['ever']}", ""]
    out.append("## Serie degli scan")
    out.append("")
    out.append("| # | quando | da guardare | info | ok | 🆕 nuovi | ✅ risolti |")
    out.append("|--:|--------|------------:|-----:|---:|--------:|----------:|")
    for i, sc in enumerate(tl["scans"], 1):
        out.append(f"| {i} | {sc['ts']} | {sc['attention']} | {sc['info']} | "
                   f"{sc['ok']} | {len(sc['new'])} | {len(sc['fixed'])} |")
    out.append("")
    out.append("## Problemi (per gravità, aperti prima)")
    out.append("")
    if not tl["issues"]:
        out.append("_Nessun problema registrato._")
    for rec in tl["issues"]:
        state = "🔴 APERTO" if rec["open"] else "🟢 risolto"
        out.append(f"- **{core.SEV_LABEL.get(rec['severity'], rec['severity'])}** "
                   f"`{rec['check']}` — {rec['target']} · {state}")
        out.append(f"  - {_age_label(rec)}")
    out.append("")
    out.append("---")
    out.append("")
    out.append("_ARIES — andamento nel tempo dalla findings-DB (memoria della "
               "sentinella). Sola lettura: nessun fatto inventato, solo gli scan "
               "già salvati._")
    return "\n".join(out) + "\n"


def timeline_html(target, tl, now=None):
    s = tl["summary"]
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    parts = ["<!doctype html>", '<html lang="it"><head>',
             '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             f"<title>ARIES — andamento: {_h(target)}</title>",
             f"<style>{_HTML_CSS}"
             "table{border-collapse:collapse;width:100%;margin:.6rem 0}"
             "th,td{border:1px solid #8884;padding:.3rem .6rem;text-align:right}"
             "th:nth-child(2),td:nth-child(2){text-align:left}"
             "</style></head><body>",
             f"<h1>ARIES — andamento: {_h(target)}</h1>",
             f'<p class="meta">Generato: {_h(ts)} · {s["scans"]} scan · '
             f"problemi aperti: {s['open']} · risolti: {s['resolved']} · "
             f"mai visti: {s['ever']}</p>",
             "<h2>Serie degli scan</h2>",
             _sparkline_svg(tl["scans"]),
             "<table><tr><th>#</th><th>quando</th><th>da guardare</th>"
             "<th>info</th><th>ok</th><th>🆕 nuovi</th><th>✅ risolti</th></tr>"]
    for i, sc in enumerate(tl["scans"], 1):
        parts.append(f"<tr><td>{i}</td><td>{_h(sc['ts'])}</td>"
                     f"<td>{sc['attention']}</td><td>{sc['info']}</td>"
                     f"<td>{sc['ok']}</td><td>{len(sc['new'])}</td>"
                     f"<td>{len(sc['fixed'])}</td></tr>")
    parts.append("</table>")
    parts.append("<h2>Problemi (per gravità, aperti prima)</h2>")
    if not tl["issues"]:
        parts.append("<p>Nessun problema registrato.</p>")
    for rec in tl["issues"]:
        color = _SEV_COLOR.get(rec["severity"], "#555")
        state = "🔴 APERTO" if rec["open"] else "🟢 risolto"
        parts.append(f'<div class="finding" style="border-left-color:{color}">')
        parts.append(f'<h3><span class="sev" style="background:{color}">'
                     f"{_h(core.SEV_LABEL.get(rec['severity'], rec['severity']))}</span> "
                     f"<code>{_h(rec['check'])}</code> — {_h(rec['target'])} · {state}</h3>")
        parts.append(f'<div class="kv">{_h(_age_label(rec))}</div>')
        parts.append("</div>")
    parts.append("<footer>ARIES — andamento nel tempo dalla findings-DB (memoria "
                 "della sentinella). Sola lettura: nessun fatto inventato, solo "
                 "gli scan già salvati.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def render_timeline(path, target, tl, now=None):
    """Sceglie il formato dall'estensione di `path` e ritorna (formato, testo)."""
    if path.lower().endswith(_HTML_EXT):
        return "html", timeline_html(target, tl, now)
    return "markdown", timeline_markdown(target, tl, now)


def write_timeline(path, target, tl, now=None):
    """Rende e scrive la dashboard di andamento su disco. Ritorna il formato."""
    fmt, text = render_timeline(path, target, tl, now)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return fmt


# --- Parco macchine (multi-bersaglio, una sola vista) ------------------------
# Testo onesto per la tendenza del conteggio «da guardare» fra gli ultimi due
# scan. La parola la decide il CODICE (findings_db.fleet), qui solo la resa.
_TREND_TXT = {"up": "▲ peggiora", "down": "▼ migliora",
              "flat": "▬ stabile", "first": "· (1° scan)"}
_TREND_SYM = {"up": "▲", "down": "▼", "flat": "▬", "first": "·"}
# colore della tendenza: salire = più problemi = rosso, scendere = verde
_TREND_COLOR = {"up": "#b00020", "down": "#2e7d32", "flat": "#777", "first": "#777"}


def _fleet_delta_txt(rec):
    """`+2` / `-1` / `=` (o vuoto al primo scan) per la colonna tendenza."""
    if rec["trend"] == "first":
        return ""
    d = rec["delta"]
    return f"+{d}" if d > 0 else (str(d) if d < 0 else "=")


def fleet_markdown(fl, now=None):
    s = fl["summary"]
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    out = ["# ARIES — parco macchine (multi-bersaglio)", "",
           f"_Generato: {ts}_", "",
           f"**Riepilogo:** {s['targets']} bersagli · con problemi aperti: "
           f"{s['with_open']} · problemi aperti in totale: {s['open_total']}", ""]
    if not fl["targets"]:
        out.append("_Nessuno scan registrato nella findings-DB._")
        out.append("")
        return "\n".join(out) + "\n"
    out.append("| bersaglio | ultimo scan | scan | aperti | peggiore | "
               "tendenza | 🆕 | ✅ |")
    out.append("|-----------|-------------|-----:|-------:|----------|"
               "----------|---:|---:|")
    for r in fl["targets"]:
        worst = core.SEV_LABEL.get(r["worst"], "—") if r["worst"] else "—"
        trend = f"{_TREND_SYM[r['trend']]} {_fleet_delta_txt(r)}".strip()
        out.append(f"| {r['target']} | {r['last_ts']} | {r['scans']} | "
                   f"{r['open']} | {worst} | {trend} | {r['new_last']} | "
                   f"{r['fixed_last']} |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("_ARIES — parco macchine dalla findings-DB (memoria della "
               "sentinella). Sola lettura: nessun fatto inventato, solo gli scan "
               "già salvati di ciascun bersaglio._")
    return "\n".join(out) + "\n"


def fleet_html(fl, now=None):
    s = fl["summary"]
    ts = now or time.strftime("%Y-%m-%d %H:%M:%S")
    parts = ["<!doctype html>", '<html lang="it"><head>',
             '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             "<title>ARIES — parco macchine</title>",
             f"<style>{_HTML_CSS}"
             "table{border-collapse:collapse;width:100%;margin:.6rem 0}"
             "th,td{border:1px solid #8884;padding:.3rem .6rem;text-align:right}"
             "th:nth-child(1),td:nth-child(1),th:nth-child(2),td:nth-child(2)"
             "{text-align:left}"
             "</style></head><body>",
             "<h1>ARIES — parco macchine</h1>",
             f'<p class="meta">Generato: {_h(ts)} · {s["targets"]} bersagli · '
             f"con problemi aperti: {s['with_open']} · problemi aperti in totale: "
             f"{s['open_total']}</p>"]
    if not fl["targets"]:
        parts.append("<p>Nessuno scan registrato nella findings-DB.</p>")
        parts.append("</body></html>")
        return "\n".join(parts) + "\n"
    parts.append("<table><tr><th>bersaglio</th><th>ultimo scan</th><th>scan</th>"
                 "<th>aperti</th><th>peggiore</th><th>tendenza</th>"
                 "<th>🆕</th><th>✅</th></tr>")
    for r in fl["targets"]:
        if r["worst"]:
            color = _SEV_COLOR.get(r["worst"], "#555")
            worst = (f'<span class="sev" style="background:{color}">'
                     f'{_h(core.SEV_LABEL.get(r["worst"], r["worst"]))}</span>')
        else:
            worst = "—"
        tcolor = _TREND_COLOR.get(r["trend"], "#777")
        trend = (f'<span style="color:{tcolor}">{_TREND_SYM[r["trend"]]} '
                 f'{_h(_fleet_delta_txt(r))}</span>')
        parts.append(f"<tr><td><code>{_h(r['target'])}</code></td>"
                     f"<td>{_h(r['last_ts'])}</td><td>{r['scans']}</td>"
                     f"<td>{r['open']}</td><td>{worst}</td><td>{trend}</td>"
                     f"<td>{r['new_last']}</td><td>{r['fixed_last']}</td></tr>")
    parts.append("</table>")
    parts.append("<footer>ARIES — parco macchine dalla findings-DB (memoria "
                 "della sentinella). Sola lettura: nessun fatto inventato, solo "
                 "gli scan già salvati di ciascun bersaglio.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def render_fleet(path, fl, now=None):
    """Sceglie il formato dall'estensione di `path` e ritorna (formato, testo)."""
    if path.lower().endswith(_HTML_EXT):
        return "html", fleet_html(fl, now)
    return "markdown", fleet_markdown(fl, now)


def write_fleet(path, fl, now=None):
    """Rende e scrive la panoramica multi-bersaglio su disco. Ritorna il formato."""
    fmt, text = render_fleet(path, fl, now)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return fmt


# --- SARIF 2.1.0 (ingestione in GitHub code scanning / pipeline SARIF-aware) --
# Perché SARIF: è il formato standard (OASIS) che GitHub "code scanning", Azure
# DevOps e molti aggregatori ingeriscono. Esportarlo porta i findings di ARIES
# nel Security tab di un repo e in qualunque pipeline SARIF-aware → PORTATA e
# USABILITÀ, senza toccare i FATTI. Come il resto di questo modulo è SOLA
# presentazione: non inventa verdetti, non tocca le severità.
#
# ONESTÀ (dottrina): ARIES NON inventa un CVSS. GitHub userebbe la proprietà
# `security-severity` (un numero 0–10) per il bucket Critical/High/… → sarebbe un
# numero finto. Qui NON la emettiamo: mappiamo la severità CATEGORIALE di ARIES
# sul `level` SARIF (error/warning/note), che è categoriale e onesto. Le severità
# `ok` (controllo PASSATO, nessun problema) NON diventano risultati: in SARIF un
# risultato è un'osservazione/problema, non l'assenza di esso → un bersaglio
# pulito produce ZERO risultati (verde nel Security tab), che è esattamente giusto.
_SARIF_EXT = (".sarif", ".sarif.json")
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_INFO_URI = "https://github.com/ManusTheGallicPlague/aries"

# Severità categoriale ARIES → livello SARIF (categoriale, nessun CVSS inventato):
# crit/high = problema da correggere → error; med/low = da guardare → warning;
# info = osservazione → note; `ok` NON diventa un risultato (vedi sopra).
_SARIF_LEVEL = {"crit": "error", "high": "error", "med": "warning",
                "low": "warning", "info": "note"}


def _sarif_rule_id(check):
    """ruleId stabile per un finding: il PREFISSO del `check` (la parte prima di
    ':'), così `sqli:username` e `sqli:password` ricadono sulla stessa regola
    `sqli` — la stessa normalizzazione di `core.owasp_category`."""
    return str(check).split(":", 1)[0]


# Guida di rimedio per regola (ruleId = prefisso del check), mostrata da GitHub
# code scanning nel pannello dell'alert (`rule.help.text`). SOLA presentazione:
# una frase onesta su COSA la lane dimostra e COME si corregge — non cambia
# verdetti né severità. I prefissi senza voce qui (tooling generico) cadono sul
# fallback deterministico in `_sarif_help`.
_SARIF_HELP = {
    "idor": "Controllo di accesso rotto: un identificatore manomesso raggiunge "
            "la risorsa di un altro utente. Rimedio: autorizza ogni accesso "
            "per-oggetto lato server, non fidarti dell'id scelto dal client.",
    "cors": "CORS permissivo: il server riflette un Origin arbitrario, con "
            "credenziali. Rimedio: allowlist esplicita di origini; mai riflettere "
            "l'Origin insieme ad Access-Control-Allow-Credentials: true.",
    "csrf": "Il token anti-CSRF non è validato su un endpoint che cambia stato. "
            "Rimedio: valida un token sincronizzato, o imposta SameSite=Lax/Strict "
            "sul cookie di sessione.",
    "mass-assign": "Mass assignment: il client imposta un campo server-controlled "
            "(es. role). Rimedio: lega solo una allow-list esplicita di campi, "
            "non il corpo intero.",
    "redirect": "Open redirect: un parametro controlla la destinazione di un 3xx. "
            "Rimedio: allowlist delle destinazioni, o reindirizza solo a path "
            "relativi.",
    "traversal": "Path traversal / LFI: un parametro esce dalla radice e legge "
            "file arbitrari. Rimedio: riduci a basename, canonicalizza e confina "
            "dentro una radice consentita.",
    "api-gate": "Un endpoint che dovrebbe richiedere autenticazione risponde "
            "aperto. Rimedio: imponi autenticazione/autorizzazione sul server per "
            "ogni rotta sensibile.",
    "auth-gate": "Un'area che dovrebbe richiedere autenticazione risponde aperta. "
            "Rimedio: imponi autenticazione/autorizzazione sul server.",
    "exposure": "File o informazione sensibile servita dal web server. Rimedio: "
            "rimuovi il file dalla radice pubblica o negane l'accesso.",
    "sqli": "SQL injection: input non neutralizzato interpretato come query. "
            "Rimedio: query parametrizzate (prepared statement), mai concatenare "
            "l'input nella query.",
    "sqli-time": "SQL injection cieca (time-based): un ritardo controllato "
            "dall'input prova l'esecuzione. Rimedio: query parametrizzate.",
    "xss": "Cross-site scripting riflesso: input non neutralizzato eseguito nel "
            "browser. Rimedio: output-encoding per contesto e una CSP robusta.",
    "stored-xss": "Cross-site scripting persistente: input memorizzato e reso "
            "non-escapato a un'altra vittima. Rimedio: codifica in output al "
            "momento della lettura; CSP.",
    "dom-xss": "DOM-XSS lato client: una sorgente controllata dall'attaccante "
            "raggiunge un sink pericoloso. Rimedio: sink sicuri (textContent), "
            "sanitizzazione, CSP.",
    "ssti": "Server-Side Template Injection: un'espressione di template è valutata "
            "dal server. Rimedio: non passare input non fidato al motore di "
            "template; usa un contesto logic-less/sandbox.",
    "nosqli": "NoSQL operator injection: un operatore (es. $ne) nel login è "
            "valutato come query. Rimedio: coerci i valori a stringa e valida i "
            "tipi prima di costruire la query.",
    "crlf": "CRLF / HTTP response splitting: un CR-LF nell'input spezza un header "
            "di risposta. Rimedio: rimuovi CR/LF dai valori che finiscono negli "
            "header di risposta.",
    "race": "Race condition / TOCTOU: richieste concorrenti aggirano un vincolo "
            "once-only. Rimedio: transazioni atomiche, lock, o un vincolo di "
            "unicità a livello di store.",
    "header": "Security header di protezione mancante. Rimedio: imposta l'header "
            "appropriato (HSTS / CSP / X-Content-Type-Options / X-Frame-Options).",
    "security-headers": "Security header di protezione mancanti. Rimedio: imposta "
            "gli header appropriati (HSTS / CSP / nosniff / X-Frame-Options).",
    "server-banner": "Il server rivela versione/tecnologia nel banner. Rimedio: "
            "minimizza gli header informativi (Server / X-Powered-By).",
    "cookie-flags": "Cookie di sessione senza Secure e/o HttpOnly. Rimedio: "
            "imposta Secure, HttpOnly (e SameSite) sui cookie sensibili.",
    "cookie-samesite": "Cookie di sessione senza un SameSite efficace (None o "
            "assente). Rimedio: SameSite=Lax o Strict per arginare il CSRF.",
    "hsts-maxage": "HSTS presente ma inerte (max-age=0 o assente). Rimedio: "
            "max-age significativo (es. 31536000) con includeSubDomains.",
    "csp-xss": "CSP presente ma inerte contro l'XSS ('unsafe-inline' senza "
            "nonce/hash, o nessun script-src/default-src). Rimedio: CSP con "
            "nonce o hash, senza 'unsafe-inline'.",
    "xcto-nosniff": "X-Content-Type-Options presente ma ≠ nosniff → MIME-sniffing "
            "ancora attivo. Rimedio: X-Content-Type-Options: nosniff.",
    "xfo-clickjack": "X-Frame-Options presente ma inerte (ALLOW-FROM deprecato o "
            "valore ignoto). Rimedio: DENY o SAMEORIGIN, o una CSP "
            "frame-ancestors.",
    "tls": "Igiene TLS/transport: certificato scaduto/non valido o protocollo "
            "deprecato (<TLS 1.2). Rimedio: certificato valido e disabilita i "
            "protocolli obsoleti.",
    "graphql": "Debolezze GraphQL: introspection esposta, field suggestion, "
            "batching senza limite, mutation via GET/form (CSRF). Rimedio: "
            "disabilita l'introspection in produzione, limita batching e "
            "profondità, esigi application/json + token per le mutation.",
    "auth": "Login senza throttling/lockout → brute-force. Rimedio: rate-limit, "
            "lockout progressivo, autenticazione a più fattori.",
    "jwt": "Debolezze JWT: alg=none, chiave HS debole, exp ignorata. Rimedio: "
            "pinna l'algoritmo atteso, usa una chiave robusta, verifica exp.",
    "ssrf": "SSRF: il server segue un URL scelto dal client. Rimedio: allowlist "
            "di destinazioni, blocca gli IP interni/metadata, non seguire i "
            "redirect verso destinazioni non fidate.",
    "deps": "Dipendenza con CVE note. Rimedio: aggiorna il componente alla "
            "versione corretta.",
}


def _sarif_help(rid):
    """Testo di rimedio per la regola `rid` (prefisso del check). Deterministico:
    la voce dedicata in `_SARIF_HELP` se c'è, altrimenti un fallback onesto che
    rimanda al README (il verdetto resta prodotto dal codice, con la prova
    allegata). Sola presentazione."""
    return _SARIF_HELP.get(rid) or (
        f"Controllo ARIES `{rid}`: il verdetto è prodotto dal codice con la "
        f"prova (PoC) allegata al finding; vedi il README per la lane e la sua "
        f"guardia anti falso positivo.")


def to_sarif(title, findings, now=None):
    """Rende i findings in un log SARIF 2.1.0 (dict pronto per `json.dumps`).
    **PURA** (nessun I/O, nessuna rete): deterministica dato l'input → testabile
    da sola (self-check `SARIF`). Solo presentazione: verdetti e severità restano
    quelli delle lane. `now` è ignorato (SARIF non porta un timestamp obbligatorio):
    accettato per uniformità di firma col resto del modulo → output STABILE.

    - un `run` unico, driver `ARIES`; il titolo in `automationDetails.id`;
    - `rules`: le regole DISTINTE presenti (per ruleId = prefisso del check),
      ordinate, ciascuna col tag OWASP 2021 se noto;
    - `results`: un risultato per ogni finding che NON è `ok` (un controllo
      passato non è un risultato SARIF); `level` dalla severità categoriale
      (NESSUN `security-severity` numerico inventato — vedi dottrina);
    - `message` = `check` + verdetto (+ prova se presente); il PoC `curl` (già
      mascherato `$TOKEN`/`$COOKIE` dalle lane) va in `properties.repro`;
    - `locations`: il `target` come `artifactLocation.uri` (dove vive il finding);
    - `partialFingerprints.ariesCheckTarget` = `check|target` (la stessa impronta
      della sentinella/findings-DB) → GitHub deduplica i risultati fra run."""
    # regole DISTINTE (ruleId = prefisso) dai soli finding che diventano risultati
    rids = {}
    for f in findings:
        if f.get("severity") == "ok":
            continue                       # un controllo passato NON è un risultato
        rids.setdefault(_sarif_rule_id(f["check"]), None)
    ordered = sorted(rids)
    rules = []
    for i, rid in enumerate(ordered):
        rids[rid] = i                      # ruleId → ruleIndex (stabile)
        tags = ["security"]
        owasp = core.owasp_category(rid)
        if owasp:
            tags.append(owasp)
        # CWE (MITRE) → tag `external/cwe/cwe-NNN`, la convenzione che GitHub code
        # scanning legge per mostrare la debolezza sull'alert (stile CodeQL).
        # Zero-padding a 3 cifre (cwe-022, cwe-089, cwe-1336). Fatto oggettivo,
        # non inventato: una lane a output eterogeneo (graphql/deps) non ne porta.
        for n in core.cwe_ids(rid):
            tags.append(f"external/cwe/cwe-{n:03d}")
        rules.append({"id": rid, "name": rid,
                      "shortDescription": {"text": f"ARIES lane `{rid}`"},
                      "help": {"text": _sarif_help(rid)},
                      "properties": {"tags": tags}})
    results = []
    for f in findings:
        sev = f.get("severity")
        if sev == "ok":
            continue
        rid = _sarif_rule_id(f["check"])
        msg = f"{f['check']}: {f['verdict']}"
        if f.get("evidence"):
            msg += f" — {f['evidence']}"
        props = {"ariesSeverity": core.SEV_LABEL.get(sev, sev)}
        if f.get("owasp"):
            props["owasp"] = f["owasp"]
        if f.get("note"):
            props["note"] = f["note"]
        if f.get("repro"):
            props["repro"] = f["repro"]     # PoC già mascherato dalle lane
        results.append({
            "ruleId": rid, "ruleIndex": rids[rid],
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(f["target"])}}}],
            "partialFingerprints": {
                "ariesCheckTarget": f"{f['check']}|{f['target']}"},
            "properties": props})
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ARIES",
                "informationUri": _SARIF_INFO_URI,
                "rules": rules}},
            "automationDetails": {"id": title},
            "results": results}]}


# --- JUnit XML (report CI: i runner mostrano le vulnerabilità come test rossi) --
_JUNIT_EXT = (".xml", ".junit.xml")

# Severità categoriale ARIES → esito JUnit (categoriale, NESSUN CVSS inventato):
# crit/high/med/low = problema "da guardare" → <failure> (il runner lo mostra
# ROSSO); info = osservazione → <skipped> (né passato né fallito); ok = controllo
# passato → <testcase> SENZA figli (verde). Mappa ONESTA: il report mostra le
# vulnerabilità come test FALLITI, gli ok come test passati (copertura), gli info
# come saltati — a differenza del SARIF (dove `ok` NON è un risultato), qui un
# test-report ha senso anche sui passaggi: documentano cosa è stato controllato.
_JUNIT_PROBLEM = ("crit", "high", "med", "low")


def _junit_classname(check):
    """classname JUnit = PREFISSO del check (la parte prima di ':'), come il
    ruleId SARIF: raggruppa `sqli:username`/`sqli:password` sotto `sqli` → il
    runner li mostra nella stessa classe."""
    return str(check).split(":", 1)[0]


def to_junit(title, findings, now=None):
    """Rende i findings in un report JUnit XML (stringa pronta da scrivere).
    **PURA** (nessun I/O, nessuna rete): deterministica dato l'input → testabile
    da sola (self-check `JUNIT`). Solo presentazione: verdetti e severità restano
    quelli delle lane.

    Il formato JUnit è lo standard de-facto che i runner CI (GitHub via
    test-reporter, GitLab, Jenkins, CircleCI…) ingeriscono per mostrare
    «N passati / F falliti»: qui ogni vulnerabilità diventa un test **fallito**.

    Mappa ONESTA severità→esito (categoriale, NESSUN CVSS numerico):
      - crit/high/med/low (problema "da guardare") → <failure> → test ROSSO;
      - info (osservazione) → <skipped> (né passato né fallito);
      - ok (controllo passato) → <testcase> senza figli → test verde (copertura).
    Ogni finding è un <testcase> (classname = prefisso del check, name =
    `check — target`); il <failure> porta `message`=verdetto e `type`=etichetta
    CATEGORIALE (CRIT/ALTO/…), e nel corpo prova/nota/PoC (già mascherato
    `$TOKEN`/`$COOKIE` dalle lane). Tutto è XML-escapato da ElementTree → un
    payload XSS nell'evidenza resta TESTO, non rompe il documento (come
    l'escaping dell'export HTML)."""
    import xml.etree.ElementTree as ET
    ts = now or time.strftime("%Y-%m-%dT%H:%M:%S")
    n_fail = sum(1 for f in findings if f.get("severity") in _JUNIT_PROBLEM)
    n_skip = sum(1 for f in findings if f.get("severity") == "info")
    counts = {"name": "ARIES", "tests": str(len(findings)),
              "failures": str(n_fail), "errors": "0", "skipped": str(n_skip)}
    suites = ET.Element("testsuites", dict(counts, name=f"ARIES: {title}"))
    suite = ET.SubElement(suites, "testsuite", dict(counts, timestamp=ts))
    for f in findings:
        sev = f.get("severity")
        tc = ET.SubElement(suite, "testcase", {
            "classname": _junit_classname(f["check"]),
            "name": f"{f['check']} — {f['target']}"})
        if sev in _JUNIT_PROBLEM:
            body = [f"verdetto: {f['verdict']}"]
            if f.get("owasp"):
                body.append(f"OWASP: {f['owasp']}")
            if f.get("evidence"):
                body.append(f"prova: {f['evidence']}")
            if f.get("note"):
                body.append(f"nota: {f['note']}")
            if f.get("repro"):
                body.append("")
                body.append("PoC (riproduce il finding):")
                body.append(f["repro"])            # già mascherato dalle lane
            fail = ET.SubElement(tc, "failure", {
                "message": f["verdict"],
                "type": core.SEV_LABEL.get(sev, sev)})   # categoriale, mai un CVSS
            fail.text = "\n".join(body)
        elif sev == "info":
            ET.SubElement(tc, "skipped", {"message": f["verdict"]})
        # sev == "ok" → nessun figlio → <testcase> passato (copertura, verde)
    xml = ET.tostring(suites, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n"


# --- dispatch su estensione --------------------------------------------------
def render(path, title, findings, sentinella=None, now=None):
    """Sceglie il formato dall'estensione di `path` e ritorna (formato, testo).
    `.sarif`/`.sarif.json` → SARIF 2.1.0; `.xml`/`.junit.xml` → JUnit XML;
    `.html`/`.htm` → HTML; altrimenti Markdown (default esplicito e sicuro)."""
    low = path.lower()
    if low.endswith(_SARIF_EXT):
        import json as _json
        return "sarif", _json.dumps(to_sarif(title, findings, now),
                                    ensure_ascii=False, indent=2) + "\n"
    if low.endswith(_JUNIT_EXT):
        return "junit", to_junit(title, findings, now)
    if low.endswith(_HTML_EXT):
        return "html", to_html(title, findings, sentinella, now)
    return "markdown", to_markdown(title, findings, sentinella, now)


def write(path, title, findings, sentinella=None, now=None):
    """Rende e scrive il referto su disco. Ritorna il formato scelto."""
    fmt, text = render(path, title, findings, sentinella, now)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return fmt
