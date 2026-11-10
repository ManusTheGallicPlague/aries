"""Findings-DB — la MEMORIA di ARIES. Salva ogni scan e lo confronta col
precedente dello stesso bersaglio.

È ciò che trasforma uno scanner (foto istantanea) in una SENTINELLA:
  🆕 nuovi   — problemi comparsi dall'ultima volta (anche regressioni)
  ✅ risolti — problemi spariti (il fix ha tenuto)
  =  invariati

Identità di un problema (fingerprint) = check + dove. Un problema conta solo se
è "da guardare" (severità crit/high/med/low); i rinvii "ok" non sono problemi,
ma se un 'ok' torna problema la sua fingerprint ricompare tra i nuovi → regressione.

SQLite stdlib in ~/aries/aries.db. Nessuna dipendenza.
"""

import json
import os
import sqlite3
import time

DB = os.path.join(os.path.dirname(__file__), "aries.db")
_ISSUE = ("crit", "high", "med", "low")


def _conn():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS scans"
              "(id INTEGER PRIMARY KEY, target TEXT, ts TEXT, findings TEXT)")
    return c


def _issue_fps(findings):
    return {f"{f['check']}|{f['target']}" for f in findings if f["severity"] in _ISSUE}


def last_scan(target):
    c = _conn()
    row = c.execute("SELECT findings FROM scans WHERE target=? ORDER BY id DESC LIMIT 1",
                    (target,)).fetchone()
    c.close()
    return json.loads(row[0]) if row else None


def diff(target, findings):
    """Confronta i problemi di ORA con quelli dell'ultimo scan (prima di salvare)."""
    curr = _issue_fps(findings)
    prev_scan = last_scan(target)
    if prev_scan is None:
        return {"first": True, "new": sorted(curr), "fixed": [], "persistent": []}
    prev = _issue_fps(prev_scan)
    return {"first": False,
            "new": sorted(curr - prev),
            "fixed": sorted(prev - curr),
            "persistent": sorted(curr & prev)}


def save(target, findings):
    c = _conn()
    c.execute("INSERT INTO scans(target, ts, findings) VALUES(?,?,?)",
              (target, time.strftime("%Y-%m-%d %H:%M:%S"),
               json.dumps(findings, ensure_ascii=False)))
    c.commit()
    c.close()


def history(target):
    """Tutti gli scan salvati di un bersaglio, dal più VECCHIO al più recente
    (l'ordine temporale naturale per leggere l'andamento). Sola LETTURA: non
    tocca il DB. Ritorna una lista di dict {"ts", "findings"} (vuota se il
    bersaglio non è mai stato scansionato)."""
    c = _conn()
    rows = c.execute("SELECT ts, findings FROM scans WHERE target=? ORDER BY id ASC",
                     (target,)).fetchall()
    c.close()
    return [{"ts": ts, "findings": json.loads(fj)} for ts, fj in rows]


def targets():
    """Elenco dei bersagli DISTINTI presenti nella findings-DB, dal più
    RECENTEMENTE scansionato al più vecchio (ordine utile per il parco macchine).
    Sola LETTURA: non tocca il DB. Ritorna una lista di stringhe (vuota se non
    c'è ancora alcuno scan)."""
    c = _conn()
    rows = c.execute(
        "SELECT target FROM scans GROUP BY target ORDER BY MAX(id) DESC"
    ).fetchall()
    c.close()
    return [t for (t,) in rows]


def _issue_map(findings):
    """fingerprint 'check|target' → finding, per i soli problemi 'da guardare'
    (crit/high/med/low; gli 'ok'/'info' non sono problemi — stessa definizione
    di fingerprint della sentinella, vedi `_issue_fps`). Pura, nessuna rete."""
    return {f"{f['check']}|{f['target']}": f
            for f in findings if f.get("severity") in _ISSUE}


def timeline(scans):
    """Calcola l'ANDAMENTO NEL TEMPO di una serie di scan dello stesso
    bersaglio — la memoria della sentinella resa leggibile. È una funzione
    **PURA**: nessuna rete, nessun DB (prende la lista GIÀ ordinata, dal più
    vecchio al più recente, di dict {"ts", "findings"}) → deterministica e
    testabile con scan sintetici.

    Ritorna un dict:
      - "scans": un record per scan, nell'ordine temporale, con
          {ts, total, attention, info, ok, new:[fp], fixed:[fp]} dove `new`/
          `fixed` sono il delta rispetto allo scan PRECEDENTE (il primo scan ha
          new=tutti i problemi correnti, fixed=[], come la sentinella alla prima
          foto);
      - "issues": un record per ogni problema MAI comparso (fingerprint unico),
          {fp, check, target, severity, first_seen, last_seen, occurrences, open}
          dove `severity` è l'ULTIMA osservata (un problema può cambiare
          gravità nel tempo), `occurrences` quanti scan lo contengono, `open` se
          è ancora presente nell'ULTIMO scan (vero) o è stato risolto (falso);
      - "summary": {scans, ever, open, resolved}.
    Problema = finding a severità crit/high/med/low (gli 'ok'/'info' non sono
    problemi). L'ordinamento dei problemi è deterministico: prima gli aperti,
    poi per gravità (dal più grave), poi per fingerprint."""
    scan_rows = []
    issues = {}                 # fp → record aggregato nel tempo
    prev_fps = None
    for sc in scans:
        fmap = _issue_map(sc["findings"])
        curr = set(fmap)
        if prev_fps is None:    # prima foto: tutto ciò che è problema è "nuovo"
            new, fixed = sorted(curr), []
        else:
            new, fixed = sorted(curr - prev_fps), sorted(prev_fps - curr)
        by = {}
        for f in sc["findings"]:
            by[f.get("severity")] = by.get(f.get("severity"), 0) + 1
        attn = sum(v for k, v in by.items() if k in _ISSUE)
        info = by.get("info", 0)
        total = len(sc["findings"])
        scan_rows.append({"ts": sc["ts"], "total": total, "attention": attn,
                          "info": info, "ok": total - attn - info,
                          "new": new, "fixed": fixed})
        for fp, f in fmap.items():
            rec = issues.get(fp)
            if rec is None:
                issues[fp] = {"fp": fp, "check": f["check"], "target": f["target"],
                              "severity": f["severity"], "first_seen": sc["ts"],
                              "last_seen": sc["ts"], "occurrences": 1}
            else:
                rec["severity"] = f["severity"]   # l'ULTIMA gravità osservata
                rec["last_seen"] = sc["ts"]
                rec["occurrences"] += 1
        prev_fps = curr
    last_fps = prev_fps or set()
    for fp, rec in issues.items():
        rec["open"] = fp in last_fps
    order = {"crit": 0, "high": 1, "med": 2, "low": 3}
    issue_list = sorted(issues.values(),
                        key=lambda r: (not r["open"], order.get(r["severity"], 9), r["fp"]))
    open_n = sum(1 for r in issue_list if r["open"])
    return {"scans": scan_rows, "issues": issue_list,
            "summary": {"scans": len(scan_rows), "ever": len(issue_list),
                        "open": open_n, "resolved": len(issue_list) - open_n}}


_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3}


def fleet(per_target):
    """Panoramica MULTI-BERSAGLIO (il «parco macchine» in una sola vista): dato
    un record {"target", "scans"} per bersaglio (ciascuno la lista ordinata di
    scan, come la ritorna `history`), deriva per ognuno un riepilogo dell'ultimo
    stato e della tendenza. È una funzione **PURA** (riusa `timeline`, nessuna
    rete, nessun DB) → deterministica e testabile con scan sintetici.

    Per ogni bersaglio con almeno uno scan ritorna:
      {target, scans, last_ts, open, resolved, ever, worst, trend, delta,
       new_last, fixed_last}
    dove:
      - open/resolved/ever  → dal riepilogo di `timeline` (problemi aperti
        nell'ULTIMO scan · già risolti · mai visti);
      - worst  → la gravità PEGGIORE fra i problemi APERTI (None se il bersaglio
        è pulito ora);
      - trend/delta  → la variazione del conteggio «da guardare» fra gli ULTIMI
        due scan ("up"=peggiora, "down"=migliora, "flat"=stabile, "first"=un solo
        scan, niente storia); `delta` è l'intero con segno;
      - new_last/fixed_last  → 🆕/✅ dell'ultimo scan (rispetto al precedente).

    Ordinamento DETERMINISTICO: prima i bersagli con problemi aperti (per gravità
    peggiore, poi per numero di aperti decrescente), i puliti in fondo, infine per
    nome di bersaglio. I record senza alcuno scan sono SALTATI (niente da dire).
    Ritorna {"targets": [...], "summary": {targets, open_total, with_open}}."""
    recs = []
    for entry in per_target:
        scans = entry["scans"]
        if not scans:
            continue
        tl = timeline(scans)
        s = tl["summary"]
        open_issues = [r for r in tl["issues"] if r["open"]]
        worst = None
        if open_issues:
            worst = min(open_issues,
                        key=lambda r: _SEV_RANK.get(r["severity"], 9))["severity"]
        rows = tl["scans"]
        last = rows[-1]
        if len(rows) >= 2:
            delta = last["attention"] - rows[-2]["attention"]
            trend = "up" if delta > 0 else ("down" if delta < 0 else "flat")
        else:
            delta, trend = 0, "first"
        recs.append({
            "target": entry["target"], "scans": s["scans"],
            "last_ts": last["ts"], "open": s["open"], "resolved": s["resolved"],
            "ever": s["ever"], "worst": worst, "trend": trend, "delta": delta,
            "new_last": len(last["new"]), "fixed_last": len(last["fixed"]),
        })
    recs.sort(key=lambda r: (r["worst"] is None,
                             _SEV_RANK.get(r["worst"], 9),
                             -r["open"], r["target"]))
    open_total = sum(r["open"] for r in recs)
    with_open = sum(1 for r in recs if r["open"])
    return {"targets": recs,
            "summary": {"targets": len(recs), "open_total": open_total,
                        "with_open": with_open}}
