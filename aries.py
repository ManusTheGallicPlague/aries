#!/usr/bin/env python3
"""ARIES — motore unificato di security testing locale.

Sottocomandi:
  check  <url>     igiene web deterministica (sola lettura)
  fuzz   [target]  fuzzing di un parser (discovery, trova crash/DoS)
  attack <url>     test ATTIVI (SQLi) — manda payload, solo su host in allowlist
  bench            valida la lane SQLi contro un fixture vulnerabile locale (dà un punteggio)

Ogni comando accetta --json (output strutturato, per comporre lane o darlo all'LLM).
Confine: solo host in config.ALLOWLIST (tua infrastruttura + lab).
"""

import argparse
import sys

import os

import core
import lane_check
import lane_fuzz
import lane_attack
import lane_secrets
import lane_semgrep
import lane_trivy
import lane_nuclei
import lane_xss
import lane_discover
import lane_auth
import lane_idor
import lane_dom_xss
import lane_race
import lane_redirect
import lane_cors
import lane_openapi
import lane_jwt
import lane_ssti
import lane_nosqli
import lane_storedxss
import lane_csrf
import lane_massassign
import lane_ssrf
import lane_traversal
import lane_tls
import lane_graphql
import lane_crlf
import lane_xxe
import findings_db
import interpret
import report


def _out(title, findings, as_json):
    print(core.to_json(title, findings) if as_json else core.to_text(title, findings))


def _session(a):
    """Costruisce la sessione dai flag CLI --cookie/--token/--header (se il
    comando li espone), per testare la superficie LOGGATA. None se assenti →
    comportamento di default invariato."""
    return core.make_session(cookie=getattr(a, "cookie", None),
                             token=getattr(a, "token", None),
                             header=getattr(a, "header", None))


def cmd_check(a):
    _out(a.url, lane_check.run(a.url, session=_session(a)), a.json)


def cmd_fuzz(a):
    _out(a.target or "formula.py", lane_fuzz.run(a.target), a.json)


def cmd_attack(a):
    print("⚠️  lane ATTIVA: manda payload. Solo su host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_attack.run(a.url, field=a.field, send_as=a.send_as, session=_session(a)), a.json)


def cmd_secrets(a):
    _out(a.path, lane_secrets.run(a.path, history=a.history), a.json)


def cmd_sast(a):
    _out(a.path, lane_semgrep.run(a.path, config=a.config), a.json)


def _is_url(t):
    return t.startswith("http://") or t.startswith("https://")


def cmd_scan(a):
    """Compone le lane applicabili al bersaglio, poi fa il diff di regressione."""
    target = a.target
    sess = _session(a)                                     # sessione per la superficie loggata
    findings = []
    if _is_url(target):
        findings += lane_check.run(target, session=sess)   # web, sola lettura
        if a.active:
            print("⚠️  --active: includo test SQLi + XSS (manda payload).", file=sys.stderr)
            findings += lane_attack.run(target, field=a.field, session=sess)
            findings += lane_xss.run(target, param=a.field, session=sess)
    else:
        findings += lane_secrets.run(target)               # codice: segreti
        findings += lane_semgrep.run(target)               # codice: vulnerabilità
        findings += lane_trivy.run(target)                 # dipendenze: CVE note

    d = findings_db.diff(target, findings)                 # diff PRIMA di salvare
    findings_db.save(target, findings)

    report_info = None
    if a.report:                                           # referto Markdown/HTML
        fmt = report.write(a.report, f"scan {target}", findings, sentinella=d)
        report_info = {"path": a.report, "format": fmt}

    # gate di CI ASSOLUTO: findings >= soglia su TUTTO il debito (exit ≠ 0 in fondo)
    gate_hits = core.gate(findings, a.fail_on) if a.fail_on else []
    gate_info = ({"threshold": a.fail_on, "tripped": bool(gate_hits),
                  "count": len(gate_hits)} if a.fail_on else None)

    # gate di CI di REGRESSIONE: findings >= soglia ma SOLO tra i nuovi della
    # sentinella. Al primo scan non c'è baseline con cui regredire → niente trip
    # (la sentinella marcherebbe tutto "nuovo": sarebbe il gate assoluto).
    new_fps = [] if d["first"] else d["new"]
    gate_new_hits = core.gate_new(findings, a.fail_on_new, new_fps) if a.fail_on_new else []
    gate_new_info = ({"threshold": a.fail_on_new, "tripped": bool(gate_new_hits),
                      "count": len(gate_new_hits), "first_scan": d["first"]}
                     if a.fail_on_new else None)

    if a.json:
        import json as _json
        obj = {"target": target, "findings": findings,
               "summary": core._summary(findings), "sentinella": d}
        if report_info:
            obj["report"] = report_info
        if gate_info:
            obj["fail_on"] = gate_info
        if gate_new_info:
            obj["fail_on_new"] = gate_new_info
        if a.explain:
            obj["interpretazione"] = interpret.interpret(target, findings)
        print(_json.dumps(obj, ensure_ascii=False, indent=2))
        if gate_hits or gate_new_hits:
            sys.exit(1)
        return

    print(core.to_text(f"scan {target}", findings))
    print("\n== SENTINELLA (confronto con lo scan precedente) ==")
    if d["first"]:
        print("  primo scan di questo bersaglio → baseline salvata.")
    else:
        print(f"  🆕 nuovi problemi : {len(d['new'])}")
        for x in d["new"]:
            print(f"       + {x}")
        print(f"  ✅ risolti        : {len(d['fixed'])}")
        for x in d["fixed"]:
            print(f"       - {x}")
        print(f"  =  invariati      : {len(d['persistent'])}")

    if report_info:
        print(f"\n== REFERTO ({report_info['format']}) scritto in: {report_info['path']} ==")

    if a.explain:
        print("\n== INTERPRETAZIONE (Qwen 14B — da verificare contro i fatti sopra) ==")
        print(interpret.interpret(target, findings))

    if a.fail_on:
        lab = core.SEV_LABEL.get(a.fail_on, a.fail_on)
        print(f"\n== GATE ASSOLUTO (--fail-on {a.fail_on}) ==")
        if gate_hits:
            print(f"  ❌ {len(gate_hits)} finding ≥ {lab} → exit 1 (gate CI fallito)")
            for f in gate_hits:
                print(f"       {core.SEV_LABEL.get(f['severity'], f['severity'])}: {f['check']}")
        else:
            print(f"  ✅ nessun finding ≥ {lab} → exit 0")

    if a.fail_on_new:
        lab = core.SEV_LABEL.get(a.fail_on_new, a.fail_on_new)
        print(f"\n== GATE REGRESSIONE (--fail-on-new {a.fail_on_new}) ==")
        if d["first"]:
            print(f"  ✅ primo scan di questo bersaglio → baseline salvata, "
                  f"nessuna regressione da valutare → exit 0")
        elif gate_new_hits:
            print(f"  ❌ {len(gate_new_hits)} finding NUOVO ≥ {lab} → exit 1 (regressione)")
            for f in gate_new_hits:
                print(f"       {core.SEV_LABEL.get(f['severity'], f['severity'])}: {f['check']}|{f['target']}")
        else:
            print(f"  ✅ nessun finding NUOVO ≥ {lab} (il debito preesistente non "
                  f"conta) → exit 0")

    if gate_hits or gate_new_hits:
        sys.exit(1)


def cmd_history(a):
    """Andamento nel tempo di un bersaglio: legge la findings-DB (la memoria
    della sentinella) e mostra la SERIE degli scan e i problemi con la loro ETÀ.
    Sola LETTURA: non lancia nessuna lane, non tocca il DB → nessun payload, nessun
    confine da imporre (non raggiunge la rete). Il cuore del calcolo è la funzione
    PURA `findings_db.timeline`. Senza `target` mostra invece il PARCO MACCHINE
    (panoramica multi-bersaglio, tutti i bersagli della findings-DB in una sola
    vista) via `cmd_fleet`."""
    if not a.target:
        return cmd_fleet(a)
    scans = findings_db.history(a.target)
    tl = findings_db.timeline(scans)

    report_info = None
    if a.report:
        fmt = report.write_timeline(a.report, a.target, tl)
        report_info = {"path": a.report, "format": fmt}

    if a.json:
        import json as _json
        obj = {"target": a.target, "timeline": tl}
        if report_info:
            obj["report"] = report_info
        print(_json.dumps(obj, ensure_ascii=False, indent=2))
        return

    s = tl["summary"]
    print(f"\n=== ARIES — andamento: {a.target} ===")
    if not scans:
        print("  questo bersaglio non è mai stato scansionato "
              "(nessuno scan nella findings-DB) → esegui prima `aries scan`.")
        return
    print(f"(scan: {s['scans']} · problemi aperti: {s['open']} · "
          f"risolti: {s['resolved']} · mai visti: {s['ever']})\n")
    print("== SERIE DEGLI SCAN (dal più vecchio) ==")
    for i, sc in enumerate(tl["scans"], 1):
        print(f"  {i:>2}. {sc['ts']}  da guardare:{sc['attention']:>3}  "
              f"info:{sc['info']:>3}  ok:{sc['ok']:>3}  "
              f"🆕{len(sc['new'])}  ✅{len(sc['fixed'])}")
        for fp in sc["new"]:
            print(f"        🆕 + {fp}")
        for fp in sc["fixed"]:
            print(f"        ✅ - {fp}")
    print("\n== PROBLEMI (per gravità, aperti prima) ==")
    if not tl["issues"]:
        print("  nessun problema registrato.")
    for rec in tl["issues"]:
        state = "🔴 APERTO " if rec["open"] else "🟢 risolto"
        tag = core.SEV_LABEL.get(rec["severity"], rec["severity"])
        print(f"  {state} [{tag:5}] {rec['check']} — {rec['target']}")
        print(f"             {report._age_label(rec)}")

    if report_info:
        print(f"\n== REFERTO ({report_info['format']}) scritto in: {report_info['path']} ==")


def cmd_fleet(a):
    """Parco macchine: la panoramica MULTI-BERSAGLIO (tutti i bersagli della
    findings-DB in una sola vista — l'ultimo stato e la tendenza di ciascuno),
    là dove `history <target>` guarda un solo bersaglio. Sola LETTURA: non lancia
    lane, non tocca il DB, non raggiunge la rete. Il cuore è la funzione PURA
    `findings_db.fleet`."""
    per_target = [{"target": t, "scans": findings_db.history(t)}
                  for t in findings_db.targets()]
    fl = findings_db.fleet(per_target)

    report_info = None
    if a.report:
        fmt = report.write_fleet(a.report, fl)
        report_info = {"path": a.report, "format": fmt}

    if a.json:
        import json as _json
        obj = {"fleet": fl}
        if report_info:
            obj["report"] = report_info
        print(_json.dumps(obj, ensure_ascii=False, indent=2))
        return

    s = fl["summary"]
    print("\n=== ARIES — parco macchine (multi-bersaglio) ===")
    if not fl["targets"]:
        print("  nessuno scan registrato nella findings-DB → esegui prima "
              "`aries scan` su almeno un bersaglio.")
        return
    print(f"(bersagli: {s['targets']} · con problemi aperti: {s['with_open']} · "
          f"problemi aperti in totale: {s['open_total']})\n")
    print("== BERSAGLI (i più a rischio prima) ==")
    _TREND = {"up": "▲ peggiora", "down": "▼ migliora",
              "flat": "▬ stabile", "first": "· 1° scan"}
    for r in fl["targets"]:
        worst = core.SEV_LABEL.get(r["worst"], "—") if r["worst"] else "—"
        flag = "🔴" if r["open"] else "🟢"
        delta = report._fleet_delta_txt(r)
        print(f"  {flag} [{worst:5}] aperti:{r['open']:>3}  {_TREND[r['trend']]}"
              f"{(' ' + delta) if delta else ''}  🆕{r['new_last']} ✅{r['fixed_last']}"
              f"  · {r['scans']} scan, ultimo {r['last_ts']}")
        print(f"          {r['target']}")

    if report_info:
        print(f"\n== REFERTO ({report_info['format']}) scritto in: {report_info['path']} ==")


def cmd_deps(a):
    _out(a.path, lane_trivy.run(a.path), a.json)


def cmd_nuclei(a):
    print("⚠️  lane ATTIVA: nuclei manda richieste al bersaglio. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_nuclei.run(a.url, severity=a.severity), a.json)


def cmd_xss(a):
    print("⚠️  lane ATTIVA: inietta payload XSS. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_xss.run(a.url, param=a.param, send_as=a.send_as, session=_session(a)), a.json)


def cmd_discover(a):
    print("⚠️  lane ATTIVA: ffuf sonda molti percorsi. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_discover.run(a.url, wordlist=a.wordlist), a.json)


def cmd_auth(a):
    print("⚠️  lane ATTIVA: manda login falliti (username finto). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_auth.run(a.url, field=a.field, send_as=a.send_as, attempts=a.attempts), a.json)


def cmd_idor(a):
    print("⚠️  lane ATTIVA: accede a risorse con id diversi. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_idor.run(a.url, id_param=a.param, owned=a.owned, other=a.other,
                              identity_header=a.id_header, identity=a.identity, token=a.token), a.json)


def cmd_dom_xss(a):
    print("⚠️  lane ATTIVA: carica la pagina in un browser e inietta payload. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_dom_xss.run(a.url), a.json)


def cmd_race(a):
    print("⚠️  lane ATTIVA: manda richieste CONCORRENTI. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_race.run(a.url, method=a.method, concurrency=a.concurrency,
                              body=a.body, session=_session(a)), a.json)


def cmd_redirect(a):
    print("⚠️  lane ATTIVA: inietta payload di redirect (canary esterno MAI contattato). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_redirect.run(a.url, param=a.param, allowed=a.allowed, session=_session(a)), a.json)


def cmd_crlf(a):
    print("⚠️  lane ATTIVA: inietta CR-LF nel parametro per spezzare un header di risposta. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_crlf.run(a.url, param=a.param, session=_session(a)), a.json)


def cmd_cors(a):
    print("⚠️  lane ATTIVA: manda un Origin arbitrario al bersaglio. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_cors.run(a.url, session=_session(a)), a.json)


def cmd_openapi(a):
    print("⚠️  lane ATTIVA: gira xss/sqli/auth/idor sugli endpoint dichiarati dallo spec "
          "(auth manda login falliti con username finto; idor cambia l'id della risorsa "
          "con la TUA identità). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    lanes = tuple(s.strip() for s in a.lanes.split(",") if s.strip())
    _out(a.spec, lane_openapi.run(a.spec, base=a.base, lanes=lanes,
                                  token=a.token, id_header=a.id_header, identity=a.identity,
                                  owned=a.owned, other=a.other), a.json)


def cmd_jwt(a):
    print("⚠️  lane ATTIVA: forgia token e li manda all'endpoint. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_jwt.run(a.url, a.token, wordlist=a.wordlist), a.json)


def cmd_ssti(a):
    print("⚠️  lane ATTIVA: inietta espressioni template. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_ssti.run(a.url, param=a.param, send_as=a.send_as, session=_session(a)), a.json)


def cmd_nosqli(a):
    print("⚠️  lane ATTIVA: inietta operatori NoSQL nel login. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_nosqli.run(a.url, user_field=a.user_field, pass_field=a.pass_field,
                                user=a.user, send_as=a.send_as, session=_session(a)), a.json)


def cmd_stored_xss(a):
    print("⚠️  lane ATTIVA: scrive un payload XSS e lo rilegge da un secondo endpoint. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.write_url, lane_storedxss.run(a.write_url, a.read_url, param=a.param,
                                         write_as=a.send_as, session=_session(a)), a.json)


def cmd_csrf(a):
    print("⚠️  lane ATTIVA: manda richieste che CAMBIANO STATO. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    from urllib.parse import parse_qs
    extra = {k: v[0] for k, v in parse_qs(a.data).items()} if a.data else None
    _out(a.url, lane_csrf.run(a.url, cookie=a.cookie, token=a.token,
                              token_field=a.token_field, send_as=a.send_as, extra=extra), a.json)


def cmd_massassign(a):
    print("⚠️  lane ATTIVA: scrive un campo privilegiato su un endpoint e rilegge lo stato. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    from urllib.parse import parse_qs
    legit = {k: v[0] for k, v in parse_qs(a.data).items()} if a.data else None
    _out(a.write_url, lane_massassign.run(a.write_url, read_url=a.read_url, field=a.field,
                                          value=a.value, legit=legit, send_as=a.send_as,
                                          cookie=a.cookie), a.json)


def cmd_ssrf(a):
    print("⚠️  lane ATTIVA: inietta un URL-canary locale nel parametro. Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_ssrf.run(a.url, param=a.param, send_as=a.send_as, method=a.method,
                              session=_session(a)), a.json)


def cmd_traversal(a):
    print("⚠️  lane ATTIVA: inietta payload di path traversal (../etc/passwd). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_traversal.run(a.url, param=a.param, send_as=a.send_as, method=a.method,
                                   session=_session(a)), a.json)


def cmd_tls(a):
    print("⚠️  lane ATTIVA: apre una connessione TLS al bersaglio (solo handshake). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.target, lane_tls.run(a.target, cafile=a.cafile), a.json)


def cmd_graphql(a):
    print("⚠️  lane ATTIVA: manda query a un endpoint GraphQL (introspection/suggestion/batching/CSRF da mutation via GET/form). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_graphql.run(a.url, session=_session(a)), a.json)


def cmd_xxe(a):
    print("⚠️  lane ATTIVA: POST di un XML con entità esterna SYSTEM (file:///etc/passwd). Solo host in allowlist (tuoi/lab).", file=sys.stderr)
    _out(a.url, lane_xxe.run(a.url, session=_session(a)), a.json)


def _report_selfcheck(findings):
    """Verifica deterministica dell'export referto (feature di presentazione,
    NON una lane → non entra nel punteggio /24). Rende gli stessi findings del
    bench in Markdown e HTML e controlla invarianti oggettive:
      1. ogni PoC (repro) non vuoto compare NEL referto — Markdown verbatim,
         HTML nella forma escaped (così i payload `<script>`/`&` restano PoC
         validi e non rompono la pagina);
      2. i gruppi di severità sono ordinati dal più grave (crit prima di ok);
      3. il conteggio dei gruppi `##` in Markdown = severità distinte presenti.
    Ritorna (ok: bool, dettaglio: str)."""
    import html as _html
    md = report.to_markdown("selfcheck", findings, now="fisso")
    ht = report.to_html("selfcheck", findings, now="fisso")
    repros = [f["repro"] for f in findings if f.get("repro")]
    for r in repros:
        if r not in md:
            return False, f"PoC assente dal Markdown: {r[:60]}"
        if _html.escape(r) not in ht:
            return False, f"PoC assente dall'HTML: {r[:60]}"
    sevs_present = {f["severity"] for f in findings}
    want_groups = len(sevs_present)
    got_groups = md.count("\n## ")
    if got_groups != want_groups:
        return False, f"gruppi severità: attesi {want_groups}, trovati {got_groups}"
    # ordine: le posizioni dei titoli di gruppo seguono SEV_ORDER crescente
    order = [core.SEV_ORDER.get(s, 9) for s in sevs_present]
    positions = sorted(((md.find(f"## {core.SEV_LABEL.get(s, s)} ("), s)
                        for s in sevs_present))
    ranks = [core.SEV_ORDER.get(s, 9) for _, s in positions]
    if ranks != sorted(ranks):
        return False, "gruppi severità non ordinati dal più grave"
    return True, f"{len(repros)} PoC presenti, {want_groups} gruppi ordinati (MD+HTML)"


def _failon_selfcheck():
    """Verifica deterministica del gate di CI `scan --fail-on` (control-flow,
    NON una lane → non entra nel punteggio /30). Nessuna rete: costruisce
    findings sintetici a severità nota e controlla invarianti oggettive:
      1. conteggi per soglia (crit=1, high=2, med=3, low=4 sui 6 livelli);
      2. monotonìa/inclusione a catena crit ⊆ high ⊆ med ⊆ low;
      3. info/ok non fanno MAI scattare un gate di attenzione (fino a low);
      4. la soglia `crit` isola esattamente i soli finding `crit`.
    Ritorna (ok: bool, dettaglio: str)."""
    fs = [core.finding("c", "t", "v", s)
          for s in ("crit", "high", "med", "low", "info", "ok")]
    g = {thr: core.gate(fs, thr) for thr in ("crit", "high", "med", "low")}
    if [len(g["crit"]), len(g["high"]), len(g["med"]), len(g["low"])] != [1, 2, 3, 4]:
        return False, "conteggi per soglia errati"
    ids = lambda gg: {f["severity"] for f in gg}
    if not (ids(g["crit"]) <= ids(g["high"]) <= ids(g["med"]) <= ids(g["low"])):
        return False, "gate non monotòno (inclusione a catena violata)"
    if any(f["severity"] in ("info", "ok") for f in g["low"]):
        return False, "info/ok hanno fatto scattare il gate di attenzione"
    if ids(g["crit"]) != {"crit"}:
        return False, "la soglia crit non isola i soli finding crit"
    return True, "gate monotòno crit⊆high⊆med⊆low, info/ok inerti (exit-code CI)"


def _failonnew_selfcheck():
    """Verifica deterministica del gate di REGRESSIONE `scan --fail-on-new`
    (control-flow, NON una lane → non entra nel punteggio /30). Nessuna rete:
    findings sintetici a severità nota + un insieme di fingerprint 'nuove' e
    controlla le invarianti che distinguono il gate di regressione da quello
    assoluto:
      1. scatta solo sui finding la cui fingerprint è tra i NUOVI (il debito
         preesistente, anche se più grave, NON fa scattare);
      2. dentro il sottoinsieme nuovo vale la stessa soglia monotòna di `gate`
         (crit ⊆ high ⊆ med ⊆ low), info/ok mai;
      3. insieme 'nuovi' vuoto (primo scan/baseline) → non scatta mai, nemmeno
         con un crit presente.
    Ritorna (ok: bool, dettaglio: str)."""
    fs = [core.finding("a", "t1", "v", "crit"),   # NUOVO + crit
          core.finding("b", "t2", "v", "high"),   # VECCHIO + high (debito)
          core.finding("c", "t3", "v", "low"),    # NUOVO + low
          core.finding("d", "t4", "v", "info")]   # NUOVO + info (mai un problema)
    new = {"a|t1", "c|t3", "d|t4"}                 # 'b|t2' è debito preesistente
    fp = lambda gg: {f"{f['check']}|{f['target']}" for f in gg}
    # 1+2: soglia high → solo il crit NUOVO (il high 'b' è debito → escluso;
    #      il low 'c' è nuovo ma sotto soglia → escluso)
    if fp(core.gate_new(fs, "high", new)) != {"a|t1"}:
        return False, "soglia high: deve isolare il solo crit NUOVO (niente debito, niente sotto-soglia)"
    # soglia low → crit+low nuovi, mai l'info 'd' né il debito 'b'
    if fp(core.gate_new(fs, "low", new)) != {"a|t1", "c|t3"}:
        return False, "soglia low: devono comparire i soli nuovi crit+low (info escluso, debito escluso)"
    # 1 (forte): il debito preesistente 'b|t2' non compare per NESSUNA soglia
    if any("b|t2" in fp(core.gate_new(fs, thr, new)) for thr in ("crit", "high", "med", "low")):
        return False, "il debito preesistente (b|t2) ha fatto scattare il gate di regressione"
    # monotonìa dentro il sottoinsieme nuovo
    if not (fp(core.gate_new(fs, "crit", new)) <= fp(core.gate_new(fs, "high", new))
            <= fp(core.gate_new(fs, "med", new)) <= fp(core.gate_new(fs, "low", new))):
        return False, "gate di regressione non monotòno sui nuovi"
    # 3: insieme nuovo vuoto (primo scan) → inerte anche col crit presente
    if core.gate_new(fs, "crit", set()) != []:
        return False, "insieme 'nuovi' vuoto: il gate di regressione deve restare inerte (baseline)"
    return True, "scatta solo sui NUOVI ≥ soglia (debito preesistente e baseline inerti)"


def _history_selfcheck():
    """Verifica deterministica dell'ANDAMENTO NEL TEMPO (`aries history`, feature
    di presentazione read-only sulla findings-DB, NON una lane → non entra nel
    punteggio /N, come il referto e i gate). Nessuna rete, nessun DB: alimenta
    la funzione PURA `findings_db.timeline` con scan sintetici a severità/esito
    noti e controlla le invarianti che la rendono onesta:
      1. la serie degli scan calcola new/fixed come la sentinella (primo scan →
         tutti i problemi 'nuovi'; poi delta rispetto al precedente);
      2. gli 'ok'/'info' NON sono problemi (non entrano in nessuna fingerprint);
      3. un problema che cambia gravità porta l'ULTIMA osservata;
      4. `open`/`resolved` seguono la presenza nell'ULTIMO scan;
      5. `first_seen`/`last_seen`/`occurrences` tracciano l'anzianità.
    Ritorna (ok: bool, dettaglio: str)."""
    F = lambda chk, tgt, sev: core.finding(chk, tgt, "v", sev)
    scans = [
        {"ts": "t1", "findings": [F("a", "x", "crit"), F("b", "y", "high"),
                                  F("pub", "z", "ok"), F("note", "z", "info")]},
        {"ts": "t2", "findings": [F("a", "x", "crit"), F("c", "w", "med")]},   # b risolto, c nuovo
        {"ts": "t3", "findings": [F("a", "x", "high"), F("c", "w", "med")]},   # a cambia gravità
    ]
    tl = findings_db.timeline(scans)
    sc = tl["scans"]
    # 1 — new/fixed come la sentinella; 2 — 'ok'/'info' non sono problemi
    if sc[0]["new"] != ["a|x", "b|y"] or sc[0]["fixed"] != []:
        return False, "primo scan: new deve essere TUTTI i problemi correnti (ok/info esclusi)"
    if sc[0]["attention"] != 2 or sc[0]["info"] != 1 or sc[0]["ok"] != 1:
        return False, "conteggi del primo scan errati (ok/info non separati dai problemi)"
    if sc[1]["new"] != ["c|w"] or sc[1]["fixed"] != ["b|y"]:
        return False, "secondo scan: delta new/fixed errato rispetto al precedente"
    if sc[2]["new"] != [] or sc[2]["fixed"] != []:
        return False, "terzo scan: nessun nuovo/risolto atteso (stessi problemi)"
    issues = {r["fp"]: r for r in tl["issues"]}
    if set(issues) != {"a|x", "b|y", "c|w"}:   # 'pub'/'note' (ok/info) non sono problemi
        return False, "i problemi devono escludere i finding ok/info"
    # 3 — ultima gravità osservata; 5 — anzianità
    a = issues["a|x"]
    if not (a["severity"] == "high" and a["first_seen"] == "t1"
            and a["last_seen"] == "t3" and a["occurrences"] == 3 and a["open"]):
        return False, "il problema persistente deve portare l'ULTIMA gravità e l'anzianità giusta"
    # 4 — open/resolved dalla presenza nell'ultimo scan
    if issues["b|y"]["open"] or issues["b|y"]["last_seen"] != "t1":
        return False, "il problema risolto deve risultare chiuso, ultimo avvistamento al suo ultimo scan"
    if not issues["c|w"]["open"]:
        return False, "un problema presente nell'ultimo scan deve risultare aperto"
    if tl["summary"] != {"scans": 3, "ever": 3, "open": 2, "resolved": 1}:
        return False, f"riepilogo errato: {tl['summary']}"
    # bersaglio mai scansionato → timeline vuota ma coerente (no crash)
    empty = findings_db.timeline([])
    if empty["summary"] != {"scans": 0, "ever": 0, "open": 0, "resolved": 0}:
        return False, "una serie vuota deve dare un riepilogo a zero (no crash)"
    return True, ("timeline pura: new/fixed come la sentinella, ok/info non "
                  "problemi, gravità ULTIMA osservata, open/resolved dall'ultimo "
                  "scan, anzianità (first/last/occorrenze) tracciata")


def _sparkline_selfcheck():
    """Verifica deterministica della SPARKLINE dell'andamento (grafico inline nel
    report HTML di `history`, feature di presentazione read-only, NON una lane →
    non entra nel punteggio /N, come il referto, i gate e HISTORY). Nessuna rete,
    nessun DB: asserisce sulla GEOMETRIA della funzione PURA
    `report.sparkline_points` e sull'HTML reso, invarianti che la rendono onesta:
      1. lista vuota → nessun punto; 1 conteggio → un punto CENTRATO (no /0);
      2. N conteggi → N punti, x UNIFORMI e crescenti dal bordo sinistro a quello
         destro (primo scan a sinistra, ultimo a destra);
      3. y INVERTITO e scalato sul massimo: il conteggio più ALTO sta in cima
         (y minima = pad), uno 0 sta sulla BASE (y = h-pad) → «la linea sale =
         più problemi»;
      4. serie tutta a zero → linea PIATTA sulla base (non a metà altezza);
      5. render: <2 scan → nessun SVG (la tabella basta); ≥2 scan → un <svg> con
         una <polyline> compare NEL report HTML di `history`.
    Ritorna (ok: bool, dettaglio: str)."""
    sp = report.sparkline_points
    w, h, pad = report._SPARK_W, report._SPARK_H, report._SPARK_PAD
    top, base = pad, h - pad
    # 1 — casi degeneri
    if sp([]) != []:
        return False, "serie vuota deve dare nessun punto"
    one = sp([5])
    if len(one) != 1 or round(one[0][0], 2) != round((pad + (w - pad)) / 2, 2):
        return False, "un solo scan: il punto deve essere centrato (nessuna /0)"
    # 2 — x uniformi, crescenti, dal bordo sinistro al destro
    pts = sp([0, 2, 1, 4])        # 4 scan, massimo = 4
    xs = [x for x, _ in pts]
    if len(pts) != 4:
        return False, "N conteggi devono dare N punti"
    if round(xs[0], 2) != pad or round(xs[-1], 2) != w - pad:
        return False, "il primo punto a sinistra (pad), l'ultimo a destra (w-pad)"
    dx = [round(b - a, 2) for a, b in zip(xs, xs[1:])]
    if any(d <= 0 for d in dx) or len(set(dx)) != 1:
        return False, "le x devono essere uniformi e strettamente crescenti"
    # 3 — y invertito e scalato sul massimo
    ys = [y for _, y in pts]
    if round(ys[0], 2) != base:               # conteggio 0 → base (in basso)
        return False, "un conteggio 0 deve stare sulla BASE (y = h-pad)"
    if round(ys[3], 2) != top:                # conteggio massimo (4) → cima
        return False, "il conteggio MASSIMO deve stare in cima (y = pad)"
    if not (ys[1] < ys[0] and ys[2] > ys[1]): # 2 più in alto di 0; 1 più in basso di 2
        return False, "y deve essere invertito: più alto il conteggio, più piccola la y"
    # 4 — tutto a zero → piatto sulla base (non a metà)
    flat = sp([0, 0, 0])
    if any(round(y, 2) != base for _, y in flat):
        return False, "una serie tutta a zero deve dare una linea PIATTA sulla base"
    # 5 — render nell'HTML di `history`: <2 scan niente SVG, ≥2 scan un <svg>+<polyline>
    rows1 = [{"attention": 3}]
    rows2 = [{"attention": 1}, {"attention": 4}, {"attention": 2}]
    if report._sparkline_svg(rows1) != "":
        return False, "con meno di 2 scan non deve esserci sparkline"
    svg = report._sparkline_svg(rows2)
    if "<svg" not in svg or "<polyline" not in svg or "max 4 da guardare" not in svg:
        return False, "con ≥2 scan la sparkline deve essere un <svg> con <polyline>"
    F = lambda chk, tgt, sev: core.finding(chk, tgt, "v", sev)
    tl = findings_db.timeline([
        {"ts": "t1", "findings": [F("a", "x", "high")]},
        {"ts": "t2", "findings": [F("a", "x", "high"), F("b", "y", "med")]},
    ])
    ht = report.timeline_html("http://127.0.0.1:8099/app", tl, now="fisso")
    if "<svg" not in ht or "<polyline" not in ht:
        return False, "il report HTML di `history` deve includere la sparkline inline"
    return True, ("sparkline pura: N punti, x uniformi dal bordo sx al dx, y "
                  "invertito/scalato sul massimo (0→base, max→cima), tutto-zero "
                  "piatto; <2 scan nessun SVG, ≥2 un <svg>+<polyline> nel report HTML")


def _fleet_selfcheck():
    """Verifica deterministica del PARCO MACCHINE (panoramica multi-bersaglio di
    `aries history` senza target, feature di presentazione read-only, NON una
    lane → non entra nel punteggio /N, come il referto, i gate, HISTORY e
    SPARKLINE). Nessuna rete, nessun DB: asserisce sulla funzione PURA
    `findings_db.fleet` con bersagli sintetici, le invarianti che la rendono
    onesta:
      1. serie vuota → nessun bersaglio, riepilogo a zero (no crash);
      2. un bersaglio senza scan è SALTATO (niente da dire);
      3. `worst` è la gravità PEGGIORE fra i soli problemi APERTI: un problema
         più grave ma RISOLTO non la peggiora (prova il bug sottile);
      4. `trend`/`delta` seguono il conteggio «da guardare» fra gli ultimi due
         scan (sale→"up"/+, scende→"down"/−, un solo scan→"first");
      5. ordinamento: i bersagli con problemi aperti prima (per gravità peggiore,
         poi più aperti), i puliti in fondo, infine per nome;
      6. render: la tabella HTML del parco include i bersagli; un parco vuoto lo
         dichiara senza crash.
    Ritorna (ok: bool, dettaglio: str)."""
    F = lambda chk, tgt, sev: core.finding(chk, tgt, "v", sev)
    # 1 — serie vuota
    empty = findings_db.fleet([])
    if empty["targets"] != [] or empty["summary"] != {"targets": 0, "open_total": 0,
                                                       "with_open": 0}:
        return False, "un parco vuoto deve dare nessun bersaglio e riepilogo a zero"
    per_target = [
        # A: 2 scan, attention 1→2 (sale), worst crit, 🆕1 h
        {"target": "A", "scans": [
            {"ts": "t1", "findings": [F("c", "A", "crit")]},
            {"ts": "t2", "findings": [F("c", "A", "crit"), F("h", "A", "high")]}]},
        # B: 2 scan, attention 2→1 (scende), worst high, ✅1 (med risolto)
        {"target": "B", "scans": [
            {"ts": "t1", "findings": [F("h", "B", "high"), F("m", "B", "med")]},
            {"ts": "t2", "findings": [F("h", "B", "high")]}]},
        # F: crit RISOLTO, high aperto → worst deve essere high, non crit
        {"target": "F", "scans": [
            {"ts": "t1", "findings": [F("c", "F", "crit")]},
            {"ts": "t2", "findings": [F("h", "F", "high")]}]},
        # C: un solo scan → trend "first", worst low
        {"target": "C", "scans": [
            {"ts": "t1", "findings": [F("l", "C", "low")]}]},
        # D: ultimo scan pulito → worst None, sorta in fondo
        {"target": "D", "scans": [
            {"ts": "t1", "findings": [F("h", "D", "high")]},
            {"ts": "t2", "findings": [F("ok", "D", "ok")]}]},
        # E: nessuno scan → saltato
        {"target": "E", "scans": []},
    ]
    fl = findings_db.fleet(per_target)
    rec = {r["target"]: r for r in fl["targets"]}
    # 2 — E saltato
    if "E" in rec or fl["summary"]["targets"] != 5:
        return False, "un bersaglio senza scan deve essere saltato"
    # 3 — worst solo sugli APERTI
    if rec["F"]["worst"] != "high":
        return False, "worst deve ignorare i problemi RISOLTI (crit risolto ≠ worst)"
    if rec["A"]["worst"] != "crit" or rec["D"]["worst"] is not None:
        return False, "worst = gravità peggiore fra gli aperti (None se pulito)"
    # 4 — trend/delta
    if rec["A"]["trend"] != "up" or rec["A"]["delta"] != 1 or rec["A"]["new_last"] != 1:
        return False, "A: attention 1→2 deve dare trend up, delta +1, 🆕1"
    if rec["B"]["trend"] != "down" or rec["B"]["delta"] != -1 or rec["B"]["fixed_last"] != 1:
        return False, "B: attention 2→1 deve dare trend down, delta −1, ✅1"
    if rec["C"]["trend"] != "first" or rec["C"]["delta"] != 0:
        return False, "C: un solo scan deve dare trend 'first' (niente storia)"
    # 5 — ordinamento: aperti per gravità peggiore, puliti in fondo, poi per nome
    names = [r["target"] for r in fl["targets"]]
    if names != ["A", "B", "F", "C", "D"]:
        return False, f"ordine errato: {names} (atteso crit·high(B<F)·low·pulito)"
    if fl["summary"]["with_open"] != 4 or fl["summary"]["open_total"] != 5:
        return False, f"riepilogo errato: {fl['summary']}"
    # 6 — render HTML
    ht = report.fleet_html(fl, now="fisso")
    if "<table" not in ht or "<code>A</code>" not in ht or "<code>D</code>" not in ht:
        return False, "il report HTML del parco deve includere la tabella e i bersagli"
    if "Nessuno scan" not in report.fleet_html(findings_db.fleet([]), now="fisso"):
        return False, "un parco vuoto deve dichiararlo nel report HTML, senza crash"
    return True, ("parco pura: bersaglio senza scan saltato, worst solo sugli "
                  "aperti (risolto non peggiora), trend/delta dall'ultimo passo, "
                  "ordine per gravità peggiore (puliti in fondo), tabella HTML resa")


def _sarif_selfcheck():
    """Verifica deterministica dell'export SARIF 2.1.0 (presentazione, NON una
    lane → non entra nel punteggio /N, come il referto/gate/HISTORY/SPARKLINE/
    FLEET). Nessuna rete: rende findings sintetici a severità note e asserisce le
    invarianti OGGETTIVE del formato e della MAPPA ONESTA:
      1. involucro SARIF valido — version '2.1.0', `$schema`, un solo run, driver
         'ARIES' — e il tutto è serializzabile in JSON (round-trip `dumps`/`loads`);
      2. `ok` NON diventa un risultato (un controllo passato non è un problema) →
         #results = #findings non-`ok`, nell'ordine di input;
      3. mappa severità→level ESATTA e categoriale: crit/high→error, med/low→
         warning, info→note; e NESSUN `security-severity` numerico in giro (niente
         CVSS inventato — dottrina);
      4. ogni result ha un ruleId tra le `rules` dichiarate (ruleIndex coerente),
         una location con `artifactLocation.uri` = target, e la partialFingerprint
         `check|target` (la stessa impronta della sentinella);
      5. il PoC (repro) mascherato fluisce in `properties.repro`;
      6. non-vacuità: un bersaglio TUTTO `ok` → zero results (verde nel Security
         tab), e le regole sono deduplicate per prefisso (`sqli:username` +
         `sqli:password` → UNA sola regola `sqli`).
    Ritorna (ok: bool, dettaglio: str)."""
    import json as _json
    fs = [
        core.finding("sqli:username", "http://h/login", "VULNERABILE (bypass)", "crit",
                     note="n1", evidence="e1",
                     repro="curl ... -H 'Authorization: Bearer $TOKEN'"),
        core.finding("sqli:password", "http://h/login", "VULNERABILE", "high"),
        core.finding("cors:/api", "http://h/api", "arbitraria riflessa", "med"),
        core.finding("xcto-nosniff:/x", "http://h/x", "nosniff inerte", "low"),
        core.finding("graphql:/gql", "http://h/gql", "introspection esposta", "med"),
        core.finding("cors:/pub", "http://h/pub", "API pubblica", "info"),
        core.finding("header:hsts", "http://h/", "presente", "ok"),
    ]
    doc = report.to_sarif("scan http://h", fs, now="fisso")
    # 1 — involucro + serializzabilità (round-trip)
    try:
        s = _json.dumps(doc)
        doc = _json.loads(s)
    except (TypeError, ValueError) as ex:
        return False, f"SARIF non serializzabile: {ex}"
    if doc.get("version") != "2.1.0" or "$schema" not in doc:
        return False, "involucro: version/$schema mancanti"
    runs = doc.get("runs", [])
    if len(runs) != 1:
        return False, f"atteso un solo run, trovati {len(runs)}"
    driver = runs[0]["tool"]["driver"]
    if driver.get("name") != "ARIES":
        return False, "driver non 'ARIES'"
    results, rules = runs[0]["results"], driver["rules"]
    # 2 — `ok` escluso, ordine preservato
    non_ok = [f for f in fs if f["severity"] != "ok"]
    if len(results) != len(non_ok):
        return False, f"results {len(results)} ≠ findings non-ok {len(non_ok)}"
    if any("header:hsts" in r["message"]["text"] for r in results):
        return False, "un finding 'ok' è diventato un risultato SARIF"
    # 3 — mappa severità→level esatta + nessun CVSS
    want = {"crit": "error", "high": "error", "med": "warning",
            "low": "warning", "info": "note"}
    for f, r in zip(non_ok, results):
        if r["level"] != want[f["severity"]]:
            return False, f"level errato per {f['severity']}: {r['level']}"
    if "security-severity" in s:
        return False, "security-severity presente (CVSS inventato, vietato)"
    # 4 — rules deduplicate/ordinate, ruleIndex/location/fingerprint coerenti
    rule_ids = [ru["id"] for ru in rules]
    if rule_ids != sorted(set(rule_ids)):
        return False, "rules non deduplicate/ordinate"
    if rule_ids.count("sqli") != 1:
        return False, "regola 'sqli' non deduplicata per prefisso"
    for r in results:
        if r["ruleId"] not in rule_ids:
            return False, f"ruleId {r['ruleId']} senza regola dichiarata"
        if rules[r["ruleIndex"]]["id"] != r["ruleId"]:
            return False, "ruleIndex incoerente col ruleId"
        if not r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]:
            return False, "location senza uri (target)"
        if "|" not in r["partialFingerprints"]["ariesCheckTarget"]:
            return False, "partialFingerprint check|target assente"
    # 5 — PoC mascherato in properties.repro
    r0 = results[0]
    if r0["properties"].get("repro") != fs[0]["repro"] or "$TOKEN" not in r0["properties"]["repro"]:
        return False, "PoC (repro) mascherato assente da properties"
    # 6 — non-vacuità: tutto-ok → zero results
    allok = report.to_sarif("t", [core.finding("header:x", "t", "ok", "ok")])
    if allok["runs"][0]["results"]:
        return False, "un bersaglio tutto-ok NON ha prodotto zero results"
    # 7 — arricchimento delle rules: help di rimedio + tag CWE (external/cwe/…)
    by_id = {ru["id"]: ru for ru in rules}
    for ru in rules:
        if not ru.get("help", {}).get("text"):
            return False, f"regola {ru['id']} senza help.text di rimedio"
    #   7a — CWE OGGETTIVA: la regola con CWE nota porta il tag normalizzato, e
    #        ogni tag CWE corrisponde esattamente a core.cwe_ids (nessun inventato)
    for ru in rules:
        tags = ru["properties"]["tags"]
        cwe_tags = [t for t in tags if t.startswith("external/cwe/cwe-")]
        want = [f"external/cwe/cwe-{n:03d}" for n in core.cwe_ids(ru["id"])]
        if cwe_tags != want:
            return False, f"tag CWE di {ru['id']} = {cwe_tags}, atteso {want}"
    #   7b — ancora oggettiva: sqli→CWE-89 presente, cors→CWE-942 presente
    if "external/cwe/cwe-089" not in by_id["sqli"]["properties"]["tags"]:
        return False, "sqli senza il tag CWE-89"
    if "external/cwe/cwe-942" not in by_id["cors"]["properties"]["tags"]:
        return False, "cors senza il tag CWE-942"
    #   7c — ONESTÀ: una lane a output eterogeneo (graphql) NON porta una CWE
    #        univoca → nessun tag CWE, ma HA comunque il suo help di rimedio
    if any(t.startswith("external/cwe/") for t in by_id["graphql"]["properties"]["tags"]):
        return False, "graphql (output eterogeneo) NON deve avere una CWE univoca"
    if not by_id["graphql"]["help"]["text"]:
        return False, "graphql senza help di rimedio"
    #   7d — cwe_ids è pura e onesta: lista ORDINATA di interi, [] per l'ignoto
    if core.cwe_ids("traversal:/f") != [22, 98] or core.cwe_ids("ignoto:x") != []:
        return False, "core.cwe_ids non ordinata/non-vuota per l'ignoto"
    return True, ("SARIF 2.1.0 valido: `ok` escluso (bersaglio pulito → 0 "
                  "results), severità→level categoriale (crit/high=error · "
                  "med/low=warning · info=note, nessun CVSS), rules deduplicate "
                  "per prefisso con help di rimedio + tag CWE oggettivi "
                  "(external/cwe/cwe-NNN, graphql/deps eterogenei senza CWE "
                  "univoca), fingerprint check|target, PoC mascherato in "
                  "properties → ingeribile da GitHub code scanning")


def _junit_selfcheck():
    """Verifica deterministica dell'export JUnit XML (presentazione, NON una
    lane → non entra nel punteggio /N, come SARIF/referto/gate/HISTORY/FLEET).
    Nessuna rete: rende findings sintetici a severità note e asserisce le
    invarianti OGGETTIVE del formato JUnit e della MAPPA ONESTA:
      1. XML BEN FORMATO (parsabile) — root <testsuites>, un solo <testsuite>,
         driver 'ARIES';
      2. mappa severità→esito categoriale: crit/high/med/low → <failure> (test
         ROSSO), info → <skipped>, ok → <testcase> SENZA figli (verde/copertura);
      3. conteggi coerenti negli attributi: tests = #findings, failures =
         #problemi, skipped = #info, errors = 0;
      4. <failure> porta message=verdetto e type=etichetta CATEGORIALE (CRIT/…),
         NESSUN numero CVSS inventato; il PoC mascherato ($TOKEN) fluisce nel corpo;
      5. classname = prefisso del check (sqli:username + sqli:password → stesso
         classname `sqli`);
      6. robustezza: un payload <script> nell'evidenza resta TESTO (XML escapato),
         il documento resta ben formato e non nasce un elemento figlio spurio;
      7. non-vacuità: un bersaglio tutto-`ok` → failures=0, skipped=0, N testcase
         passati senza figli (verde nel runner CI).
    Ritorna (ok: bool, dettaglio: str)."""
    import xml.etree.ElementTree as ET
    fs = [
        core.finding("sqli:username", "http://h/login", "VULNERABILE (bypass)", "crit",
                     note="n1", evidence="e1",
                     repro="curl ... -H 'Authorization: Bearer $TOKEN'"),
        core.finding("sqli:password", "http://h/login", "VULNERABILE", "high"),
        core.finding("cors:/api", "http://h/api", "arbitraria riflessa", "med"),
        core.finding("xcto-nosniff:/x", "http://h/x", "nosniff inerte", "low"),
        core.finding("xss:q", "http://h/s", "riflessa <script>alert(1)</script>", "high"),
        core.finding("cors:/pub", "http://h/pub", "API pubblica", "info"),
        core.finding("header:hsts", "http://h/", "presente", "ok"),
    ]
    text = report.to_junit("scan http://h", fs, now="2026-01-01T00:00:00")
    # 1 — XML ben formato (il parse È la prova di serializzabilità) + involucro
    try:
        root = ET.fromstring(text)
    except ET.ParseError as ex:
        return False, f"JUnit XML non ben formato: {ex}"
    if root.tag != "testsuites":
        return False, f"root non <testsuites> ma <{root.tag}>"
    suites = root.findall("testsuite")
    if len(suites) != 1:
        return False, f"atteso un solo <testsuite>, trovati {len(suites)}"
    suite = suites[0]
    if suite.get("name") != "ARIES":
        return False, "testsuite name non 'ARIES'"
    cases = suite.findall("testcase")
    problem = ("crit", "high", "med", "low")
    n_fail = sum(1 for f in fs if f["severity"] in problem)
    n_skip = sum(1 for f in fs if f["severity"] == "info")
    # 3 — conteggi coerenti
    if len(cases) != len(fs):
        return False, f"testcase {len(cases)} ≠ findings {len(fs)}"
    if (suite.get("tests") != str(len(fs)) or suite.get("failures") != str(n_fail)
            or suite.get("skipped") != str(n_skip) or suite.get("errors") != "0"):
        return False, (f"conteggi errati: tests={suite.get('tests')} "
                       f"failures={suite.get('failures')} "
                       f"skipped={suite.get('skipped')} errors={suite.get('errors')}")
    # 2+4+5 — mappa esito, type categoriale (no CVSS), classname per prefisso
    labels = set(core.SEV_LABEL.values())
    for f, tc in zip(fs, cases):
        sev = f["severity"]
        if tc.get("classname") != f["check"].split(":", 1)[0]:
            return False, f"classname errato per {f['check']}: {tc.get('classname')}"
        fail, skip = tc.find("failure"), tc.find("skipped")
        if sev in problem:
            if fail is None:
                return False, f"finding {sev} senza <failure>"
            if fail.get("message") != f["verdict"]:
                return False, "message di <failure> ≠ verdetto"
            typ = fail.get("type")
            if typ not in labels:
                return False, f"type <failure> non categoriale: {typ!r}"
            if typ.replace(".", "").isdigit():
                return False, f"type <failure> numerico (CVSS inventato): {typ!r}"
        elif sev == "info":
            if skip is None or fail is not None:
                return False, "finding info: atteso <skipped> senza <failure>"
        else:  # ok → nessun figlio
            if fail is not None or skip is not None:
                return False, "finding ok NON è un testcase passato (ha un figlio)"
    # 5b — classname deduplicato: sqli:username + sqli:password → 'sqli' su entrambi
    if sum(1 for tc in cases if tc.get("classname") == "sqli") != 2:
        return False, "classname 'sqli' non applicato a entrambi i finding sqli:*"
    # 4b — PoC mascherato nel corpo del primo <failure>
    body0 = cases[0].find("failure").text or ""
    if "$TOKEN" not in body0 or "curl" not in body0:
        return False, "PoC mascherato assente dal corpo del <failure>"
    # 6 — robustezza: il payload <script> è escapato → resta TESTO nel message, e
    #     NON nasce un elemento figlio <script> spurio (il parse ha già provato
    #     che il doc è ben formato malgrado i caratteri pericolosi)
    xss_case = [tc for tc in cases if (tc.get("name") or "").startswith("xss:q")][0]
    xfail = xss_case.find("failure")
    if xfail is None or "<script>" not in (xfail.get("message") or ""):
        return False, "payload XSS non preservato come testo nel message"
    if xss_case.find("script") is not None:
        return False, "payload XSS interpretato come elemento (escaping rotto)"
    # 7 — non-vacuità: bersaglio tutto-ok → 0 failures / 0 skipped / N passati
    allok = ET.fromstring(report.to_junit("t", [
        core.finding("header:x", "t", "ok", "ok"),
        core.finding("header:y", "t", "ok", "ok")]))
    su = allok.find("testsuite")
    if su.get("failures") != "0" or su.get("skipped") != "0":
        return False, "bersaglio tutto-ok con failures/skipped ≠ 0"
    ok_cases = su.findall("testcase")
    if len(ok_cases) != 2 or any(len(list(tc)) for tc in ok_cases):
        return False, "bersaglio tutto-ok NON ha testcase passati senza figli"
    return True, ("JUnit XML ben formato: ogni finding un <testcase> (classname = "
                  "prefisso del check); problema (crit/high/med/low) → <failure> "
                  "type categoriale (CRIT/ALTO/…, nessun CVSS), info → <skipped>, "
                  "ok → passato (copertura); PoC mascherato nel corpo; payload XSS "
                  "escapato; bersaglio pulito → failures=0 (verde nel runner CI)")


def _samesite_selfcheck(base):
    """Verifica a due facce del controllo passivo 'difesa CSRF via SameSite'
    (vive in `check`, NON è una lane attiva → non entra nel punteggio /N, come
    il referto e i gate). Due parti:
      1. END-TO-END sul fixture: `/cookie-weak` (SameSite=None) è segnalato
         DIFESA CSRF ASSENTE (MED), `/cookie-strong` (SameSite=Lax) ok — pur
         avendo entrambi Secure+HttpOnly (quindi `cookie-flags` li dice robusti:
         è la distinzione che il check sulla sola presenza non vedeva);
      2. PURE-FUNCTION: `samesite_csrf` classifica correttamente None esplicito,
         attributo assente, Lax e Strict.
    Ritorna (ok: bool, dettaglio: str)."""
    def csrf_f(fs):
        return next(f for f in fs if f["check"] == "cookie-samesite")
    w = csrf_f(lane_check._cookies(base + "/cookie-weak"))
    s = csrf_f(lane_check._cookies(base + "/cookie-strong"))
    ok_weak = w["severity"] == "med" and "ASSENTE" in w["verdict"]
    ok_strong = s["severity"] == "ok" and "presente" in s["verdict"]
    # il cookie 'weak' resta "robusto" per cookie-flags (ha i 3 attributi): è
    # proprio il falso negativo che questo check chiude (SameSite=None presente
    # ma non protettivo)
    flags_w = next(f for f in lane_check._cookies(base + "/cookie-weak") if f["check"] == "cookie-flags")
    ok_distinct = flags_w["severity"] == "ok"
    pf = (lane_check.samesite_csrf("session=x; Secure; HttpOnly; SameSite=None") == (False, "none")
          and lane_check.samesite_csrf("session=x; Secure; HttpOnly") == (False, None)
          and lane_check.samesite_csrf("session=x; SameSite=Lax") == (True, "lax")
          and lane_check.samesite_csrf("session=x; SameSite=Strict") == (True, "strict"))
    ok = ok_weak and ok_strong and ok_distinct and pf
    detail = ("SameSite=None/assente → difesa CSRF mancante (MED), Lax/Strict → ok "
              "(distinto da cookie-flags, che vede i 3 attributi presenti)"
              if ok else f"weak={w['verdict']}/{w['severity']} strong={s['verdict']}/{s['severity']} "
              f"distinct={ok_distinct} pure-fn={pf}")
    return ok, detail


def _hsts_selfcheck(base):
    """Verifica a due facce del controllo passivo 'difesa HSTS via max-age'
    (vive in `check`, NON è una lane attiva → non entra nel punteggio /N, come il
    referto, i gate e il gemello SAMESITE). Due parti:
      1. END-TO-END sul fixture: `/hsts-weak` (max-age=0) è segnalato HSTS
         DISATTIVATO (MED), `/hsts-strong` (max-age valido) ok — pur avendo
         ENTRAMBI l'header `Strict-Transport-Security` presente (quindi il
         controllo di PRESENZA `header:strict-transport-security` li dice
         entrambi "presente/ok": è la distinzione che il check sulla sola
         presenza non vedeva, un `max-age=0` presente ma inerte);
      2. PURE-FUNCTION: `hsts_active` classifica max-age=0, max-age valido,
         max-age assente e valore vuoto.
    Ritorna (ok: bool, dettaglio: str)."""
    def hf(fs):
        return next(f for f in fs if f["check"] == "hsts-maxage")
    def pres(fs):
        return next(f for f in fs if f["check"] == "header:strict-transport-security")
    hw = lane_check._headers(base + "/hsts-weak")
    hs = lane_check._headers(base + "/hsts-strong")
    w, s = hf(hw), hf(hs)
    ok_weak = w["severity"] == "med" and "DISATTIVATO" in w["verdict"]
    ok_strong = s["severity"] == "ok" and "attivo" in s["verdict"]
    # ENTRAMBI "presenti" per il controllo di presenza (header impostato): è
    # proprio il falso negativo che questo check chiude (max-age=0 presente ma
    # non protettivo), come cookie-samesite rispetto a cookie-flags.
    ok_distinct = pres(hw)["severity"] == "ok" and pres(hs)["severity"] == "ok"
    pf = (lane_check.hsts_active("max-age=0") == (False, 0)
          and lane_check.hsts_active("max-age=31536000; includeSubDomains") == (True, 31536000)
          and lane_check.hsts_active("includeSubDomains") == (False, None)
          and lane_check.hsts_active("") == (False, None))
    ok = ok_weak and ok_strong and ok_distinct and pf
    detail = ("max-age=0/assente → difesa HSTS inerte (MED), max-age>0 → ok "
              "(distinto dal controllo di presenza, che vede solo l'header impostato)"
              if ok else f"weak={w['verdict']}/{w['severity']} strong={s['verdict']}/{s['severity']} "
              f"distinct={ok_distinct} pure-fn={pf}")
    return ok, detail


def _csp_selfcheck(base):
    """Verifica a due facce del controllo passivo 'difesa XSS via CSP value-aware'
    (vive in `check`, NON è una lane attiva → non entra nel punteggio /N, come i
    gemelli SAMESITE/HSTS). Due parti:
      1. END-TO-END sul fixture: `/csp-weak` (script-src 'unsafe-inline' senza
         nonce) è segnalato CSP INERTE (MED), `/csp-strong` (script-src con nonce,
         no 'unsafe-inline') ok — pur avendo ENTRAMBI l'header
         `Content-Security-Policy` presente (quindi il controllo di PRESENZA li
         dice entrambi "presente/ok": è la distinzione che il check sulla sola
         presenza non vedeva, una CSP presente ma inerte contro l'XSS);
      2. PURE-FUNCTION: `csp_xss_active` classifica unsafe-inline senza nonce,
         unsafe-inline NEUTRALIZZATO da un nonce (CSP2+ lo ignora → difesa),
         il fallback `default-src` senza script-src, l'assenza di entrambe le
         direttive, e `unsafe-eval` da solo (NON inerte contro l'inline).
    Ritorna (ok: bool, dettaglio: str)."""
    def cf(fs):
        return next(f for f in fs if f["check"] == "csp-xss")
    def pres(fs):
        return next(f for f in fs if f["check"] == "header:content-security-policy")
    cw = lane_check._headers(base + "/csp-weak")
    cs = lane_check._headers(base + "/csp-strong")
    w, s = cf(cw), cf(cs)
    ok_weak = w["severity"] == "med" and "INERTE" in w["verdict"]
    ok_strong = s["severity"] == "ok" and "efficace" in s["verdict"]
    # ENTRAMBI "presenti" per il controllo di presenza (header impostato): è
    # proprio il falso negativo che questo check chiude (CSP presente ma inerte
    # contro l'XSS), come cookie-samesite/hsts-maxage rispetto ai loro gemelli.
    ok_distinct = pres(cw)["severity"] == "ok" and pres(cs)["severity"] == "ok"
    pf = (lane_check.csp_xss_active("default-src 'self'; script-src 'self' 'unsafe-inline'")[0] is False
          and lane_check.csp_xss_active("script-src 'self' 'unsafe-inline' 'nonce-abc'") == (True, "")
          and lane_check.csp_xss_active("default-src 'self'") == (True, "")
          and lane_check.csp_xss_active("img-src 'self'")[0] is False
          and lane_check.csp_xss_active("default-src 'self'; script-src 'unsafe-eval' 'self'") == (True, ""))
    ok = ok_weak and ok_strong and ok_distinct and pf
    detail = ("script-src 'unsafe-inline' (senza nonce/hash) o nessun script-src/default-src "
              "→ CSP inerte contro l'XSS (MED), altrimenti ok (distinto dal controllo di "
              "presenza, che vede solo l'header impostato)"
              if ok else f"weak={w['verdict']}/{w['severity']} strong={s['verdict']}/{s['severity']} "
              f"distinct={ok_distinct} pure-fn={pf}")
    return ok, detail


def _xcto_selfcheck(base):
    """Verifica a due facce del controllo passivo 'difesa MIME-sniffing via
    X-Content-Type-Options value-aware' (vive in `check`, NON è una lane attiva →
    non entra nel punteggio /N, come i gemelli SAMESITE/HSTS/CSP). Due parti:
      1. END-TO-END sul fixture: `/xcto-weak` (valore `none`, inerte) è segnalato
         NOSNIFF INERTE (LOW), `/xcto-strong` (`nosniff`) ok — pur avendo
         ENTRAMBI l'header X-Content-Type-Options presente (quindi il controllo di
         PRESENZA li dice entrambi "presente/ok": è la distinzione che il check
         sulla sola presenza non vedeva, un header presente ma inerte);
      2. PURE-FUNCTION: `xcto_active` riconosce `nosniff` (anche a case misto e
         come PRIMO token di una lista), e boccia `none`/vuoto/`nosniff` non in
         prima posizione (algoritmo "determine nosniff" di WHATWG Fetch: conta il
         primo token, case-insensitive).
    Ritorna (ok: bool, dettaglio: str)."""
    def cf(fs):
        return next(f for f in fs if f["check"] == "xcto-nosniff")
    def pres(fs):
        return next(f for f in fs if f["check"] == "header:x-content-type-options")
    xw = lane_check._headers(base + "/xcto-weak")
    xs = lane_check._headers(base + "/xcto-strong")
    w, s = cf(xw), cf(xs)
    ok_weak = w["severity"] == "low" and "INERTE" in w["verdict"]
    ok_strong = s["severity"] == "ok" and "attivo" in s["verdict"]
    # ENTRAMBI "presenti" per il controllo di presenza (header impostato): è
    # proprio il falso negativo che questo check chiude (header presente ma inerte),
    # come cookie-samesite/hsts-maxage/csp-xss rispetto ai loro gemelli.
    ok_distinct = pres(xw)["severity"] == "ok" and pres(xs)["severity"] == "ok"
    pf = (lane_check.xcto_active("nosniff") == (True, "nosniff")
          and lane_check.xcto_active("NoSniff")[0] is True
          and lane_check.xcto_active("nosniff, nosniff")[0] is True
          and lane_check.xcto_active("none")[0] is False
          and lane_check.xcto_active("")[0] is False
          and lane_check.xcto_active("sniff, nosniff")[0] is False)
    ok = ok_weak and ok_strong and ok_distinct and pf
    detail = ("X-Content-Type-Options con valore ≠ `nosniff` (primo token) → "
              "MIME-sniffing inerte (LOW), `nosniff` → ok (distinto dal controllo di "
              "presenza, che vede solo l'header impostato)"
              if ok else f"weak={w['verdict']}/{w['severity']} strong={s['verdict']}/{s['severity']} "
              f"distinct={ok_distinct} pure-fn={pf}")
    return ok, detail


def _xfo_selfcheck(base):
    """Verifica a due facce del controllo passivo 'difesa anti-clickjacking via
    X-Frame-Options value-aware' (vive in `check`, NON è una lane attiva → non
    entra nel punteggio /N, come i gemelli SAMESITE/HSTS/CSP/XCTO). Due parti:
      1. END-TO-END sul fixture: `/xfo-weak` (valore `ALLOW-FROM …`, deprecato e
         inerte) è segnalato X-FRAME-OPTIONS INERTE (LOW), `/xfo-strong` (`DENY`)
         ok — pur avendo ENTRAMBI l'header X-Frame-Options presente (quindi il
         controllo di PRESENZA li dice entrambi "presente/ok": è la distinzione
         che il check sulla sola presenza non vedeva, un header presente ma inerte);
      2. PURE-FUNCTION: `xfo_active` riconosce `DENY`/`SAMEORIGIN` (anche a case
         misto) e boccia `ALLOW-FROM …` (deprecato), vuoto e valori sconosciuti.
    Ritorna (ok: bool, dettaglio: str)."""
    def cf(fs):
        return next(f for f in fs if f["check"] == "xfo-clickjack")
    def pres(fs):
        return next(f for f in fs if f["check"] == "header:x-frame-options")
    xw = lane_check._headers(base + "/xfo-weak")
    xs = lane_check._headers(base + "/xfo-strong")
    w, s = cf(xw), cf(xs)
    ok_weak = w["severity"] == "low" and "INERTE" in w["verdict"]
    ok_strong = s["severity"] == "ok" and "attivo" in s["verdict"]
    # ENTRAMBI "presenti" per il controllo di presenza (header impostato): è
    # proprio il falso negativo che questo check chiude (header presente ma inerte),
    # come cookie-samesite/hsts-maxage/csp-xss/xcto-nosniff rispetto ai loro gemelli.
    ok_distinct = pres(xw)["severity"] == "ok" and pres(xs)["severity"] == "ok"
    pf = (lane_check.xfo_active("DENY") == (True, "deny")
          and lane_check.xfo_active("SameOrigin")[0] is True
          and lane_check.xfo_active("sameorigin")[0] is True
          and lane_check.xfo_active("ALLOW-FROM https://x.example") == (False, "allow-from")
          and lane_check.xfo_active("")[0] is False
          and lane_check.xfo_active("ALLOWALL")[0] is False)
    ok = ok_weak and ok_strong and ok_distinct and pf
    detail = ("X-Frame-Options con valore ≠ `DENY`/`SAMEORIGIN` (ALLOW-FROM "
              "deprecato, ignorato dai browser) → anti-clickjacking inerte (LOW), "
              "`DENY`/`SAMEORIGIN` → ok (distinto dal controllo di presenza, che "
              "vede solo l'header impostato)"
              if ok else f"weak={w['verdict']}/{w['severity']} strong={s['verdict']}/{s['severity']} "
              f"distinct={ok_distinct} pure-fn={pf}")
    return ok, detail


def _owasp_selfcheck(findings, base):
    """Verifica deterministica del tag di CATEGORIA OWASP Top 10 2021 (etichetta
    tassonomica derivata dal nome del check, NON una lane → non entra nel
    punteggio /N, come il referto e i gate). Niente CVSS: solo la classe, mai un
    numero. Tre parti:
      1. END-TO-END sui findings reali del bench: OGNI finding "da guardare"
         (crit/high/med/low) porta un tag OWASP non vuoto → nessuna lane attiva
         resta senza categoria (e il tag è nel dict, quindi fluisce in JSON);
      2. PURE-FUNCTION `core.owasp_category`: prefisso corretto per un campione
         di ogni categoria usata, invarianza al suffisso (`sqli:username` ≡
         `sqli`), e '' onesto per i check generici/tooling o informativi;
      3. RESO: il tag compare in `to_text` SOLO sui 'da guardare', ma è sempre
         presente in `to_json` (fedeltà macchina).
    Ritorna (ok: bool, dettaglio: str)."""
    # 1 — ogni finding reale "da guardare" è categorizzato. Copriamo SIA le lane
    # attive del bench SIA il comando passivo `check` sul fixture (è lì che vivono
    # i finding `header:*`/`cookie-*`/`*-gate`/`exposure:*`, che le sole lane
    # offensive non emettono: così la copertura non ha buchi). Unica eccezione
    # legittima e DICHIARATA: l'aggregato `openapi` del bench, un meta-finding che
    # riduce a un verdetto unico sotto-findings di CLASSI MISTE (xss/sqli/…) —
    # pinnarlo a una sola categoria sarebbe disonesto; nel run reale `openapi`
    # emette i sotto-findings, ognuno col PROPRIO tag. Lo escludiamo apposta.
    import lane_check
    coverage = list(findings) + lane_check.run(base + "/cookie-weak")
    attn = [f for f in coverage
            if f["severity"] in ("crit", "high", "med", "low") and f["check"] != "openapi"]
    missing = sorted({f["check"] for f in attn if not f.get("owasp")})
    if missing:
        return False, f"finding 'da guardare' senza tag OWASP: {missing}"
    # 2 — mapping puro: un campione per categoria + invarianza al suffisso.
    want = {
        "sqli:username": "A03", "xss:q": "A03", "stored-xss:body": "A03",
        "nosqli:password": "A03", "ssti:name": "A03", "dom-xss": "A03",
        "crlf:to": "A03",
        "idor:path": "A01", "cors": "A01", "csrf": "A01",
        "mass-assign:role": "A01", "redirect:next": "A01", "exposure:/.env": "A01",
        "traversal:file": "A01",
        "race": "A04", "deps": "A06", "tls:cert": "A02", "tls:protocol": "A02",
        "header:content-security-policy": "A05", "server-banner": "A05",
        "cookie-flags": "A05", "cookie-samesite": "A05", "hsts-maxage": "A05",
        "csp-xss": "A05", "xcto-nosniff": "A05", "xfo-clickjack": "A05",
        "graphql:introspection": "A05", "xxe:body": "A05",
        "api-gate": "A01", "auth-gate": "A01",
        "auth:bruteforce": "A07", "jwt": "A07", "ssrf:url": "A10",
    }
    for check, code in want.items():
        got = core.owasp_category(check)
        if got != core.OWASP_2021[code]:
            return False, f"owasp_category('{check}') = '{got}', atteso {code}"
    # check generici/tooling o informativi → NESSUNA categoria (onesto)
    for check in ("sast", "secrets", "nuclei", "discover", "fuzz", "openapi:spec"):
        if core.owasp_category(check) != "":
            return False, f"il check generico '{check}' non deve avere un tag OWASP"
    # 3 — reso: testo solo sui 'da guardare', JSON sempre.
    vuln = core.finding("sqli:username", "t", "VULNERABILE", "high")
    okf = core.finding("sqli:username", "t", "non rilevata", "ok")
    if "owasp: A03:2021 Injection" not in core.to_text("t", [vuln]):
        return False, "il tag OWASP non compare in to_text su un finding 'da guardare'"
    if "owasp:" in core.to_text("t", [okf]):
        return False, "il tag OWASP non deve comparire in to_text su un 'ok'"
    import json as _json
    j = _json.loads(core.to_json("t", [okf]))
    if j["findings"][0].get("owasp") != "A03:2021 Injection":
        return False, "il tag OWASP deve essere sempre presente in --json"
    cats = sorted({f["owasp"] for f in attn})
    return True, f"{len(attn)} finding categorizzati, {len(cats)} classi OWASP nel bench (no CVSS)"


def _adversarial_selfcheck(base):
    """Banco AVVERSARIALE — la 3ª faccia del benchmark (cancello GLOBALE
    anti-falso-positivo, NON una lane → non entra nel punteggio /N, come i gate e
    il referto). Mentre il bench a due facce prova *vulnerabile* + *sicuro*, qui si
    aggiunge il caso SANO MA INGANNEVOLE: endpoint non vulnerabili che SOMIGLIANO a
    esserlo. Punta OGNI lane coperta contro la sua trappola e pretende SILENZIO
    (verdetto non-VULNERABILE) — misura la robustezza di ciò che già esiste contro
    input cattivi, non solo contro i fixture a due facce.

    Le trappole (in `bench_vuln`, su 127.0.0.1): ECO VERBATIM del payload (riflette
    ma non esegue/valuta/include/fetcha), 200-A-TUTTO stile SPA (stesso corpo per
    ogni input), ECO DEGLI HEADER di richiesta (Origin/Authorization nel corpo, mai
    negli header di risposta), LATENZA casuale sotto-soglia (jitter di rete).

    Molte lane hanno GIÀ una guardia di questo tipo (la D del CSRF, il canary SSRF,
    l'esca del mass-assign, il prodotto dell'SSTI, la firma del traversal, il
    differenziale eguale-lunghezza del boolean-SQLi): qui la si rende SISTEMATICA e
    benchmarkata per tutte. Il JWT ha ottenuto in questo stesso lavoro la guardia
    che gli mancava (firma rotta di controllo: se il server l'accetta non verifica
    le firme → alg=none non attribuibile).

    IDOR (query e token) è COPERTA (era la sola lane offensiva differenziale
    esclusa): la guardia di CONTENUTO aggiunta a `lane_idor` afferma IDOR solo se,
    a parità di status 200, il corpo della risorsa altrui DIFFERISCE dal mio (dati
    per-utente); la trappola `/trap-spa` (200-a-tutto, corpo costante) dà owned=200
    ∧ other=200 ma corpi IDENTICI → la lane tace (nessun falso positivo). Una
    SECONDA guardia chiude il caso dell'endpoint ID-ECHO (`/trap-id-echo`, serve un
    guscio + l'id riflesso per QUALUNQUE id): lì i corpi DIFFERISCONO (per il solo
    id), ma una sonda su un id INESISTENTE dà comunque 200 → l'endpoint non è una
    risorsa per-id memorizzata → la lane tace (query e path).

    Auth (bruteforce) è ora COPERTA con una trappola DEDICATA (`/trap-auth-lockout`):
    un login SANO che non usa il 429 canonico ma fa lockout per TRANSIZIONE di
    status (401 ai primi tentativi, poi 403 e ci resta). A uno scanner ingenuo
    pare "nessun throttling"; la guardia `_lockout_transition` della lane riconosce
    la transizione tardiva e persistente verso uno status bloccante → la lane tace
    (nessun falso positivo "no rate-limit" su un login che SI difende). Questo
    stesso lavoro ha dato alla lane i due segnali che le mancavano: `Retry-After`
    (RFC 7231, status-agnostico) e la transizione di status, oltre al 429/423.

    Race è ora COPERTA con una guardia POST-BURST: un burst concorrente che riesce
    N× può essere una vera race OPPURE un endpoint RIPETIBILE (SPA 200-a-tutto,
    idempotente) che riesce N× per costruzione. La lane manda allora una richiesta
    SEQUENZIALE post-burst: se riesce ancora (2xx) l'operazione non è "una volta
    sola" → gli N successi non dimostrano un TOCTOU → tace. Puntata contro
    `/trap-spa` (200-a-tutto): post-burst 200 → silenzio (nessun falso positivo).

    Lane NON coperte, e perché (onestà sui limiti):
      - DOM-XSS: richiede Playwright (lane esente dal bench in cloud).
      - TLS: le trappole sono endpoint HTTP, non server TLS; il verdetto nasce
        comunque dal codice di verifica di OpenSSL, non da una stringa riflessa.

    Ritorna (ok: bool, dettaglio: str)."""
    import bench_vuln
    E, S, H, L = (base + "/trap-echo", base + "/trap-spa",
                  base + "/trap-headers", base + "/trap-latency")
    checks = [
        # SQLi (error+boolean) vs ECO: nessun errore SQL, TRUE/FALSE eguale-lunghezza
        ("SQLi", lane_attack.sqli_login(E, field="username", send_as="json")),
        # SQLi time-based vs LATENZA sotto-soglia: il ritardo non segue l'input
        ("SQLi-time", lane_attack.sqli_time_based(L, field="username", send_as="json")),
        # XSS vs SPA 200-a-tutto: il canary non si riflette
        ("XSS", lane_xss.xss_reflected(S, param="q", send_as="query")),
        # Redirect vs ECO: nessun 3xx/Location verso l'esterno
        ("Redirect", lane_redirect.redirect(E, param="to")),
        # CRLF vs ECO: il payload è riflesso nel CORPO, mai in un header di risposta
        # → l'header-sentinella non si materializza → la prova strutturale tace
        ("CRLF", lane_crlf.crlf(E, param="to")),
        # CORS vs ECO-HEADER: l'Origin è nel corpo, mai in Access-Control-Allow-Origin
        ("CORS", lane_cors.cors(H)),
        # SSTI vs ECO: payload LETTERALE riflesso, prodotto mai calcolato
        ("SSTI", lane_ssti.ssti_inject(E, param="q", send_as="query")),
        # NoSQLi vs SPA: baseline/true/false identici → nessun differenziale
        ("NoSQLi", lane_nosqli.nosqli_login(S)),
        # Stored-XSS vs SPA: il canary non riemerge dalla lettura
        ("Stored-XSS", lane_storedxss.stored_xss(S, S, param="comment")),
        # CSRF vs SPA: A/C/D identici → guardia D (sessione non determinante)
        ("CSRF", lane_csrf.csrf_probe(S, bench_vuln.CSRF_COOKIE, bench_vuln.CSRF_TOKEN)),
        # Mass-assign vs ECO: riemerge ANCHE l'esca → eco indiscriminato
        ("Mass-assign", lane_massassign.mass_assign(E, read_url=None, field="role")),
        # SSRF vs ECO: l'URL è riflesso ma mai richiesto → canary non colpito
        ("SSRF", lane_ssrf.ssrf(E, param="url")),
        # Traversal vs ECO: payload riflesso, nessuna firma di file di sistema
        ("Traversal", lane_traversal.traversal_probe(E, param="file", send_as="query")),
        # JWT vs SPA: firma non verificata (guardia) → alg=none non attribuibile
        ("JWT", lane_jwt._worst(lane_jwt.jwt_audit(S, bench_vuln.VALID_TOKEN_SAFE))),
        # GraphQL vs ECO: l'eco della query/array non produce la STRUTTURA attesa
        # (data.__schema / errors[].'Did you mean' / lista di N risultati GraphQL)
        ("GraphQL", lane_graphql._worst(lane_graphql.graphql_audit(E))),
        # IDOR (query) vs SPA 200-a-tutto: owned=200 ∧ other=200 ma CORPI IDENTICI
        # (corpo costante) → la guardia di contenuto tace (non sono dati per-utente)
        ("IDOR", lane_idor.idor(S, owned="1", other="2", identity="1")),
        # IDOR (token, id nel path) vs SPA: /trap-spa/1 e /trap-spa/2 → stesso guscio
        # → corpi identici → silenzio (nessuna "risorsa altrui accessibile" falsa)
        ("IDOR-token", lane_idor.idor(S + "/{id}", owned="1", other="2", token="tok1")),
        # IDOR (query) vs ID-ECHO: /trap-id-echo?id=1 e ?id=2 danno corpi DIVERSI
        # (riflettono l'id) → la 1ª guardia (corpi identici) NON scatta; ma un id
        # INESISTENTE dà comunque 200 → la 2ª guardia (sonda nonce) riconosce
        # l'endpoint aperto (non una risorsa per-id memorizzata) e TACE.
        ("IDOR-idecho", lane_idor.idor(base + "/trap-id-echo", owned="1", other="2", identity="1")),
        # IDOR (token, id nel path) vs ID-ECHO: /trap-id-echo/1 e /2 → corpi diversi
        # (id riflesso), nonce /trap-id-echo/999… → 200 → silenzio (anti id-echo)
        ("IDOR-idecho-path", lane_idor.idor(base + "/trap-id-echo/{id}", owned="1", other="2", token="tok1")),
        # Auth (bruteforce) vs TRAPPOLA LOCKOUT: un login che NON usa il 429
        # canonico ma passa a 403 dopo i primi tentativi (lockout per transizione).
        # La guardia di transizione (`_lockout_transition`) riconosce la difesa e
        # TACE → nessun falso positivo "no rate-limit" su un login che SI difende.
        ("Auth", lane_auth.auth_bruteforce(base + "/trap-auth-lockout", field="username", send_as="json")),
        # Race vs SPA 200-a-tutto: il burst concorrente riesce N× (per costruzione,
        # non per TOCTOU), MA la guardia post-burst manda una richiesta SEQUENZIALE
        # che riesce ancora (200) → operazione RIPETIBILE, non "una volta sola" →
        # la lane tace (nessun falso positivo "race" su un endpoint idempotente/SPA)
        ("Race", lane_race.race(S, concurrency=5)),
        # XXE vs ECO: /trap-echo riflette il corpo XML (`&xxe;` / il DOCTYPE), MAI
        # il contenuto del file → la firma `root:…:0:0:` non si materializza → la
        # prova strutturale (firma del file, non riflessione) tace (nessun FP da eco)
        ("XXE", lane_xxe.xxe_probe(E)),
    ]
    noisy = [(lbl, f["verdict"]) for lbl, f in checks
             if "VULNERABILE" in f["verdict"] or f["verdict"] == "ERRORE"]
    if noisy:
        return False, "FALSO POSITIVO/errore contro la trappola: " + \
            ", ".join(f"{l} → {v}" for l, v in noisy)
    return True, (f"{len(checks)} lane TACCIONO contro le trappole sane-ingannevoli "
                  "(eco verbatim · SPA 200-a-tutto · eco-header · latenza · lockout-per-transizione); "
                  "IDOR coperta via guardia di contenuto (corpo costante ≠ dati per-utente, "
                  "e sonda nonce: un id inesistente che dà 200 = endpoint id-echo/aperto, non FP), "
                  "Auth via guardia di transizione (401→403 persistente = lockout, non FP), "
                  "Race via guardia post-burst (sequenziale 2xx = operazione ripetibile, non TOCTOU); "
                  "non coperte: DOM-XSS (Playwright) + TLS (handshake)")


def _benchgate_selfcheck():
    """Self-check deterministico del cancello verde→exit-code (`core.bench_green`),
    il cuore del fallimento del job CI su `aries bench`. Nessuna rete: verifica la
    funzione pura su input sintetici, così il contratto resta provato a prescindere
    dallo stato dei fixture.
    - tutte le lane 2/2 + self-check OK → VERDE;
    - una lane a 1/2 (o 0/2) → ROSSO, anche con i self-check OK;
    - un self-check fallito → ROSSO, anche con tutte le lane 2/2;
    - lista lane vuota → il verde dipende dai soli self-check (degenere, ma coerente).
    NB: la lane `dom-xss` è ESENTE e il chiamante NON la passa qui → un 1/2 di
    dom-xss non deve mai far scattare il cancello (provato dal caso 'lane piena 2/2
    con dom escluso')."""
    all_green = [2] * 32                        # 32 lane non esenti, tutte a 2/2
    cases = [
        (core.bench_green(all_green, True), True, "32 lane 2/2 + self-check OK → VERDE"),
        (core.bench_green([2] * 31 + [1], True), False, "una lane a 1/2 → ROSSO"),
        (core.bench_green([2] * 31 + [0], True), False, "una lane a 0/2 → ROSSO"),
        (core.bench_green(all_green, False), False, "un self-check fallito → ROSSO"),
        (core.bench_green([2] * 31 + [1], False), False, "lane rotta + self-check rotto → ROSSO"),
        # dom-xss esente: il chiamante esclude il suo punteggio → le altre 32 a
        # 2/2 restano VERDI anche se dom-xss sarebbe 1/2 (Playwright assente)
        (core.bench_green(all_green, True), True, "dom-xss escluso (esente) → le altre 32 a 2/2 restano VERDI"),
    ]
    bad = [why for got, want, why in cases if got is not want]
    if bad:
        return False, "cancello scorretto: " + "; ".join(bad)
    return True, ("core.bench_green: VERDE ⟺ ogni lane non esente a 2/2 E ogni "
                  "self-check OK; una lane rotta o un self-check rotto → ROSSO "
                  "(exit 1); dom-xss esente non entra nel cancello")


def _session_selfcheck(base):
    """Verifica che la SESSIONE instradata in `core.probe` (priorità #1a) apra la
    superficie LOGGATA e che il PoC resti onesto (non-lane → non entra nel
    punteggio /N, come i gate e il referto). Cinque parti, contro l'endpoint
    riservato `/axss-vuln` del fixture (200 solo con sessione, altrimenti 302):

      1. PURE-FUNCTION `core.make_session`: --cookie/--token/--header producono
         gli header giusti; vuoto → None (default invariato);
      2. CONFINE: la sessione NON aggira l'ALLOWLIST (un host esterno con sessione
         resta rifiutato in probe);
      3. MERGE in probe (le tre vie instradabili): senza sessione il canary NON
         si riflette (302, login wall); con cookie, con Bearer e con header custom
         il canary torna nella pagina riservata (200) → tutte e tre raggiungono
         la superficie loggata;
      4. NIENTE FALSO POSITIVO senza sessione: la lane `xss` sul vuln riservato,
         SENZA sessione, TACE (non-VULNERABILE) → ARIES non afferma nulla su una
         superficie che non raggiunge; CON sessione invece becca l'XSS;
      5. `check` instrada la sessione: l'header di sicurezza della pagina
         AUTENTICATA (X-Frame-Options) è letto solo con la sessione; senza, si
         vede il login wall che non lo porta;
      6. PoC MASCHERATO: `as_curl(session=…)` riproduce la richiesta autenticata
         ma col Bearer → `$TOKEN` e il Cookie → `$COOKIE` (il segreto non entra
         nel referto).
    Ritorna (ok: bool, dettaglio: str)."""
    import bench_vuln
    val = bench_vuln.SESSION_VALID
    # 1 — make_session pura
    if core.make_session() is not None:
        return False, "make_session() senza argomenti deve dare None (default invariato)"
    if core.make_session(cookie="sid=x") != {"Cookie": "sid=x"}:
        return False, "make_session(cookie=) errata"
    if core.make_session(token="abc") != {"Authorization": "Bearer abc"}:
        return False, "make_session(token=) errata"
    if core.make_session(header=["X-A: 1", "X-B: 2"]) != {"X-A": "1", "X-B": "2"}:
        return False, "make_session(header=) errata"
    # 2 — confine: la sessione non aggira l'ALLOWLIST
    if "error" not in core.probe("http://evil.example/x", session={"Cookie": f"sess={val}"}):
        return False, "la sessione ha aggirato l'ALLOWLIST (confine violato)"
    # 3 — merge in probe: senza sessione niente riflesso (login wall), con ciascuna
    #     delle tre vie la pagina riservata riflette il canary.
    canary = "sess1onC4nary"
    u = base + "/axss-vuln?q=" + canary
    no = core.probe(u)
    if no.get("status") != 302 or canary in no.get("body_head", ""):
        return False, f"senza sessione atteso 302 login wall senza riflesso (status={no.get('status')})"
    for lbl, sess in (("cookie", core.make_session(cookie=f"sess={val}")),
                      ("bearer", core.make_session(token=val)),
                      ("header", core.make_session(header=[f"X-Session: {val}"]))):
        r = core.probe(u, session=sess)
        if r.get("status") != 200 or canary not in r.get("body_head", ""):
            return False, f"via {lbl}: la sessione non ha sbloccato la superficie loggata (status={r.get('status')})"
    sess = core.make_session(cookie=f"sess={val}")
    # 4 — niente FP senza sessione; con sessione becca l'XSS
    silent = lane_xss.xss_reflected(base + "/axss-vuln", param="q", send_as="query")
    if "VULNERABILE" in silent["verdict"] or silent["verdict"] == "ERRORE":
        return False, f"FALSO POSITIVO senza sessione sul login wall: {silent['verdict']}"
    caught = lane_xss.xss_reflected(base + "/axss-vuln", param="q", send_as="query", session=sess)
    if "VULNERABILE" not in caught["verdict"]:
        return False, f"con sessione l'XSS loggato NON è beccato: {caught['verdict']}"
    # 5 — `check` instrada la sessione: l'header di sicurezza X-Frame-Options è
    #     presente solo sulla pagina AUTENTICATA; sul login wall è MANCANTE → la
    #     valutazione d'igiene vede la pagina vera solo con la sessione.
    def _xfo(fs):
        return next(f for f in fs if f["check"] == "header:x-frame-options")
    xfo_auth = _xfo(lane_check._headers(base + "/axss-vuln", session=sess))
    xfo_anon = _xfo(lane_check._headers(base + "/axss-vuln"))
    if xfo_auth["verdict"] != "presente" or xfo_anon["verdict"] != "MANCANTE":
        return False, (f"check non instrada la sessione: X-Frame-Options "
                       f"auth={xfo_auth['verdict']} anon={xfo_anon['verdict']} "
                       f"(atteso presente/MANCANTE)")
    # 6 — PoC mascherato (Bearer → $TOKEN, Cookie → $COOKIE), segreto assente
    poc = core.as_curl(base + "/x", session=core.make_session(cookie="sid=SEGRETO", token="SEGRETO"))
    if "Bearer $TOKEN" not in poc or "$COOKIE" not in poc or "SEGRETO" in poc:
        return False, f"PoC non mascherato correttamente: {poc}"
    return True, ("sessione (cookie/Bearer/header) instradata in core.probe → "
                  "superficie loggata raggiunta (xss+check); senza sessione la "
                  "lane TACE (login wall, no FP); confine ALLOWLIST intatto; PoC "
                  "mascherato ($TOKEN/$COOKIE)")


def _session_threading_selfcheck(base):
    """Prova MECCANICA che OGNI lane attiva a target singolo INOLTRA la sessione
    fino a `core.probe` (priorità #1a — estensione della sessione alle altre lane
    attive). Non è una lane → non entra nel punteggio /N (come i gate e il
    referto). Il rischio di una modifica meccanica come questa è dimenticare un
    `session=` su una delle probe interne di un lane: quel buco NON lo beccherebbe
    il punteggio /2 (i fixture a due facce di quelle lane non usano la sessione),
    quindi serve un cancello dedicato.

    Metodo: per ogni lane sostituisce TEMPORANEAMENTE il binding `probe` del
    modulo-lane con una SPIA che registra il kwarg `session` ricevuto, lancia la
    lane con una sessione SENTINELLA (identità verificata con `is`), e pretende
    che ALMENO una probe l'abbia ricevuta. La spia richiama la probe vera
    (`orig`), così la lane funziona normalmente; nessuna rete nuova (solo le
    probe locali che la lane fa comunque). Deterministico.

    Copre le lane estese alla sessione: sqli (lane_attack), ssti, traversal,
    nosqli, cors, ssrf, **stored-xss, redirect** (tutte via `core.probe`) e
    **race** (che NON passa da core.probe: apre socket urllib diretti, quindi la
    sessione è provata sugli header della sua `_fire`). (xss/check sono già provate
    end-to-end dal SESSION self-check; sqli e stored-xss lo sono anche dai banchi
    Auth-SQLi/Auth-StoredXSS.)"""
    SENTINEL = {"X-Aries-Thread": "sentinel"}
    # Lane che instradano la sessione fino a `core.probe` (kwarg `session=`).
    cases = [
        ("sqli", lane_attack, lambda s: lane_attack.run(base + "/login-vuln", field="username", send_as="json", session=s)),
        ("ssti", lane_ssti, lambda s: lane_ssti.run(base + "/ssti-vuln", param="q", send_as="query", session=s)),
        ("traversal", lane_traversal, lambda s: lane_traversal.run(base + "/download-vuln", param="file", send_as="query", session=s)),
        ("nosqli", lane_nosqli, lambda s: lane_nosqli.run(base + "/nosqli-vuln", session=s)),
        ("cors", lane_cors, lambda s: lane_cors.run(base + "/cors-vuln", session=s)),
        ("ssrf", lane_ssrf, lambda s: lane_ssrf.run(base + "/ssrf-vuln", param="url", session=s)),
        ("stored-xss", lane_storedxss, lambda s: lane_storedxss.run(base + "/comment-vuln", base + "/comments-vuln", param="comment", session=s)),
        ("redirect", lane_redirect, lambda s: lane_redirect.run(base + "/redirect-vuln", param="to", session=s)),
    ]
    for name, mod, call in cases:
        seen = []
        orig = mod.probe

        def spy(*a, _orig=orig, _seen=seen, **k):
            _seen.append(k.get("session"))
            return _orig(*a, **k)

        mod.probe = spy
        try:
            call(SENTINEL)
        finally:
            mod.probe = orig
        if not any(s is SENTINEL for s in seen):
            return False, (f"lane {name}: la sessione NON è inoltrata in core.probe "
                           f"(un `session=` dimenticato nelle probe interne)")

    # Race è a parte: non usa core.probe, ma `urllib.request` via `_fire`. La
    # sessione (dict di header) deve comparire negli header di OGNI richiesta
    # concorrente → spiamo `lane_race._fire` e pretendiamo il marcatore sentinella.
    seen_hdrs = []
    orig_fire = lane_race._fire

    def fire_spy(url, method, data, headers, _orig=orig_fire, _seen=seen_hdrs):
        _seen.append(headers or {})
        return _orig(url, method, data, headers)

    lane_race._fire = fire_spy
    try:
        lane_race.run(base + "/race-safe", concurrency=3, session=SENTINEL)
    finally:
        lane_race._fire = orig_fire
    if not (seen_hdrs and all(h.get("X-Aries-Thread") == "sentinel" for h in seen_hdrs)):
        return False, ("lane race: la sessione NON è fusa negli header delle "
                       "richieste concorrenti (`_fire` senza la sessione)")

    return True, (f"{len(cases) + 1} lane attive inoltrano la sessione "
                  f"(sqli/ssti/traversal/nosqli/cors/ssrf/stored-xss/redirect via core.probe; "
                  f"race negli header di `_fire`) → la superficie LOGGATA è "
                  f"raggiungibile anche da loro; nessun `session=` perso")


def cmd_bench(a):
    import bench_vuln
    import time
    bench_vuln.serve(port=8099)
    time.sleep(0.4)
    base = "http://127.0.0.1:8099"
    sqli_v = lane_attack.sqli_login(base + "/login-vuln", field="username", send_as="json")
    sqli_s = lane_attack.sqli_login(base + "/login-safe", field="username", send_as="json")
    sqli_tb_v = lane_attack.sqli_time_based(base + "/login-vuln", field="username", send_as="json")
    sqli_tb_s = lane_attack.sqli_time_based(base + "/login-safe", field="username", send_as="json")
    xss_v = lane_xss.xss_reflected(base + "/xss-vuln", param="q", send_as="query")
    xss_s = lane_xss.xss_reflected(base + "/xss-safe", param="q", send_as="query")
    auth_v = lane_auth.auth_bruteforce(base + "/auth-norate", field="username", send_as="json")
    auth_s = lane_auth.auth_bruteforce(base + "/auth-ratelimited", field="username", send_as="json")
    idor_v = lane_idor.idor(base + "/doc-vuln", owned="1", other="2", identity="1")
    idor_s = lane_idor.idor(base + "/doc-safe", owned="1", other="2", identity="1")
    idor_br_v = lane_idor.idor(base + "/basket-vuln/{id}", owned="1", other="2", token="tok1")
    idor_br_s = lane_idor.idor(base + "/basket-safe/{id}", owned="1", other="2", token="tok1")
    dom_v = lane_dom_xss.dom_xss(base + "/dom-vuln?x=PAYLOAD")
    dom_s = lane_dom_xss.dom_xss(base + "/dom-safe?x=PAYLOAD")
    race_v = lane_race.race(base + "/race-vuln", concurrency=20)
    race_s = lane_race.race(base + "/race-safe", concurrency=20)
    red_v = lane_redirect.redirect(base + "/redirect-vuln", param="to")
    red_s = lane_redirect.redirect(base + "/redirect-safe", param="to")
    # CRLF / HTTP response header injection: il vuln scrive il valore di `to`
    # GREZZO nell'header Location → un CR-LF lo spezza e inietta un header; il safe
    # neutralizza CR/LF prima di scriverlo. Prova STRUTTURALE (l'header-sentinella
    # materializzato nella risposta), non la riflessione → la trappola eco (corpo)
    # non lo produce.
    crlf_v = lane_crlf.crlf(base + "/crlf-vuln", param="to")
    crlf_s = lane_crlf.crlf(base + "/crlf-safe", param="to")
    cors_v = lane_cors.cors(base + "/cors-vuln")
    cors_s = lane_cors.cors(base + "/cors-safe")
    cors_pf_v = lane_cors.cors(base + "/cors-preflight-vuln")   # riflessione SOLO nel preflight
    cors_pf_s = lane_cors.cors(base + "/cors-preflight-safe")
    _specs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_specs")
    oapi_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-vuln.json"), base=base, lanes=("xss", "sqli")))
    oapi_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-safe.json"), base=base, lanes=("xss", "sqli")))
    # Dispatch dal contratto → lane `auth`: lo spec dichiara un login (identità +
    # password) e l'ingestione OpenAPI ci gira il test di resistenza al brute-force.
    oapi_auth_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-auth-vuln.json"), base=base, lanes=("auth",)))
    oapi_auth_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-auth-safe.json"), base=base, lanes=("auth",)))
    # Dispatch dal contratto → lane `idor`: lo spec dichiara una GET con un id-like
    # nel path (`/basket-{vuln,safe}/{id}`) e l'autenticazione come requisito
    # (securitySchemes); l'identità (il token, che lo spec NON porta) arriva via
    # flag → l'ingestione gira l'IDOR cambiando l'id della risorsa. Riusa i fixture
    # IDOR-token esistenti (`/basket-*`, `_TOKENS`); stessa lane `idor`, superficie
    # di detection distinta (guidata dal contratto) → +2.
    oapi_idor_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-idor-vuln.json"), base=base, lanes=("idor",), token="tok1"))
    oapi_idor_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-idor-safe.json"), base=base, lanes=("idor",), token="tok1"))
    # Dispatch dal contratto con CORPO COMPOSTO: il requestBody è composto via
    # `allOf` ($ref a un modello base con `username` + un membro inline con
    # `password`). La lane `auth` dispatcha SOLO se riconosce ENTRAMBI i campi
    # (identità + password) → questa riga prova che la risoluzione della
    # composizione (`_schema_properties`) fonde i membri dell'allOf e segue il
    # `$ref` annidato. Senza il fix il contenitore `allOf` esporrebbe zero
    # proprietà → auth non dispatchato → aggregato "ok" sul vuln → 1/2 (non-vacuo).
    # Riusa i fixture auth esistenti (`/auth-norate` vuln, `/auth-ratelimited` safe).
    oapi_comp_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-compose-vuln.json"), base=base, lanes=("auth",)))
    oapi_comp_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-compose-safe.json"), base=base, lanes=("auth",)))
    # Dispatch dal contratto → lane `nosqli`: lo spec dichiara un login (identità +
    # password), lo STESSO trigger di `auth`; qui proviamo l'operator-injection NoSQL
    # sul campo identità, col transport (json/form) dettato dal content-type del
    # contratto. `nosqli` usa uno username finto (operatore sempre-vero), non tocca
    # account reali → interamente guidabile dallo spec. Riusa i fixture nosqli
    # esistenti (`/nosqli-{vuln,safe}`, body JSON che valuta/coercisce l'operatore).
    # Stessa lane `nosqli`, superficie di detection distinta (guidata dal contratto) → +2.
    oapi_nosqli_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-nosqli-vuln.json"), base=base, lanes=("nosqli",)))
    oapi_nosqli_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-nosqli-safe.json"), base=base, lanes=("nosqli",)))
    # Dispatch dal contratto → lane `ssti`: lo spec dichiara un parametro STRINGA
    # riflesso (lo stesso bersaglio di `xss`); qui proviamo la valutazione lato
    # server di un'espressione di template, non solo la riflessione. Lo spec dice
    # DOVE sta il parametro e il suo transport; la lane porta il metodo differenziale
    # (marker+prodotto calcolato = valutato → VULNERABILE; letterale = riflesso ma
    # non valutato → tace). Riusa i fixture ssti esistenti (`/ssti-{vuln,safe}?q=`,
    # il vuln passa l'input per `_tpl_render`, il safe lo escapa come dato). Stessa
    # lane `ssti`, superficie di detection distinta (guidata dal contratto) → +2.
    oapi_ssti_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-ssti-vuln.json"), base=base, lanes=("ssti",)))
    oapi_ssti_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-ssti-safe.json"), base=base, lanes=("ssti",)))
    # Dispatch dal contratto → lane `traversal`: lo spec dichiara un parametro
    # STRINGA FILE-LIKE (`file`) e `traversal` ci prova il path traversal / LFI.
    # A differenza di xss/ssti (ogni parametro stringa), mira i soli parametri
    # file-like (come `idor` sui soli id-like nel path): un `username`/`q` non è un
    # file-read. La firma è OGGETTIVA (il contenuto di /etc/passwd), non la sola
    # riflessione. Riusa i fixture traversal esistenti (`/download-{vuln,safe}?file=`:
    # il vuln fa join ingenuo → `../` esce dalla radice, il safe riduce a basename →
    # confinato). Stessa lane `traversal`, superficie di detection distinta (guidata
    # dal contratto) → +2.
    oapi_trav_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-traversal-vuln.json"), base=base, lanes=("traversal",)))
    oapi_trav_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-traversal-safe.json"), base=base, lanes=("traversal",)))
    # Dispatch dal contratto → lane `redirect`: lo spec dichiara una GET con un
    # parametro di REDIRECT nella query (`to`) e `redirect` ci prova l'open redirect.
    # A differenza di xss/ssti (ogni parametro stringa), mira i soli parametri
    # redirect-like (come `traversal` sui soli file-param, `idor` sui soli id-like):
    # un `q`/`username` non reindirizza. La firma è OGGETTIVA (un 3xx con Location
    # verso il canary ESTERNO, mai contattato), non la sola riflessione. Riusa i
    # fixture redirect esistenti (`/redirect-{vuln,safe}?to=`: il vuln segue il
    # parametro fuori, il safe valida l'origine → resta interno). Stessa lane
    # `redirect`, superficie di detection distinta (guidata dal contratto) → +2.
    oapi_red_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-redirect-vuln.json"), base=base, lanes=("redirect",)))
    oapi_red_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-redirect-safe.json"), base=base, lanes=("redirect",)))
    # Dispatch dal contratto → lane `ssrf`: lo spec dichiara una GET con un
    # parametro URL-like nella query (`url`) e `ssrf` ci prova la Server-Side
    # Request Forgery. Come traversal/redirect/idor è un dispatch SELETTIVO per
    # nome (i soli parametri URL-like), non spray come xss/ssti: un `q`/`username`
    # non innesca un fetch server-side. La prova è OGGETTIVA e out-of-band (il
    # canary locale colpito col nonce, non la riflessione). Riusa i fixture ssrf
    # esistenti (`/ssrf-{vuln,safe}?url=`: il vuln segue l'URL verso il canary, il
    # safe valida la destinazione → nessun fetch). Stessa lane `ssrf`, superficie
    # di detection distinta (guidata dal contratto) → +2. Con questa, TUTTE le
    # lane a parametro sono dispatchabili dallo spec.
    oapi_ssrf_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-ssrf-vuln.json"), base=base, lanes=("ssrf",)))
    oapi_ssrf_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-ssrf-safe.json"), base=base, lanes=("ssrf",)))
    # Dispatch dal contratto → lane `crlf`: lo spec dichiara una GET con un
    # parametro il cui valore finisce in un HEADER di risposta (`to` redirect-like,
    # il sink canonico è `Location`) e `crlf` ci prova la CRLF / response-header
    # injection. Come redirect/ssrf/traversal/idor è un dispatch SELETTIVO per nome
    # (i soli parametri header-sink: redirect-like ∪ url-like), non spray come
    # xss/ssti: un `q`/`username` non finisce in un header. La prova è OGGETTIVA e
    # STRUTTURALE (l'header-sentinella iniettato riemerge come header di risposta,
    # non la riflessione nel corpo). Riusa i fixture crlf esistenti
    # (`/crlf-{vuln,safe}?to=`: il vuln scrive `to` grezzo in Location → CR-LF
    # spezza l'header, il safe neutralizza CR/LF → nessuna injection). Stessa lane
    # `crlf`, superficie di detection distinta (guidata dal contratto) → +2.
    oapi_crlf_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-crlf-vuln.json"), base=base, lanes=("crlf",)))
    oapi_crlf_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-crlf-safe.json"), base=base, lanes=("crlf",)))
    # Dispatch dal contratto → lane `jwt`: lo spec dichiara uno schema BEARER
    # (`securitySchemes: type=http, scheme=bearer`) e una GET che lo richiede;
    # l'ingestione OpenAPI ci gira le debolezze JWT (alg=none, chiave HS debole, exp
    # ignorata). Come `idor`, lo spec dice DOVE il token è accettato ma non ne porta
    # il VALORE: il token legittimo arriva via `--token` (qui `VALID_TOKEN_*`, lo
    # stesso dei fixture jwt). Riusa gli endpoint jwt esistenti (`/jwt-{vuln,safe}`:
    # il vuln accetta alg=none/chiave debole/exp scaduta, il safe verifica tutto).
    # Stessa lane `jwt`, superficie di detection distinta (guidata dal contratto) → +2.
    oapi_jwt_v = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-jwt-vuln.json"), base=base, lanes=("jwt",),
        token=bench_vuln.VALID_TOKEN_VULN))
    oapi_jwt_s = lane_openapi.aggregate(lane_openapi.scan_spec(
        os.path.join(_specs, "openapi-jwt-safe.json"), base=base, lanes=("jwt",),
        token=bench_vuln.VALID_TOKEN_SAFE))
    jwt_v = lane_jwt._worst(lane_jwt.jwt_audit(base + "/jwt-vuln", bench_vuln.VALID_TOKEN_VULN))
    jwt_s = lane_jwt._worst(lane_jwt.jwt_audit(base + "/jwt-safe", bench_vuln.VALID_TOKEN_SAFE))
    ssti_v = lane_ssti.ssti_inject(base + "/ssti-vuln", param="q", send_as="query")
    ssti_s = lane_ssti.ssti_inject(base + "/ssti-safe", param="q", send_as="query")
    nosqli_v = lane_nosqli.nosqli_login(base + "/nosqli-vuln")
    nosqli_s = lane_nosqli.nosqli_login(base + "/nosqli-safe")
    # NoSQLi bracket-notation (form-urlencoded `campo[$op]=`, vettore Express/PHP):
    # il vuln ricostruisce i dict annidati → operatore valutato; il safe no.
    nosqli_br_v = lane_nosqli.nosqli_login(base + "/nosqli-br-vuln", send_as="form")
    nosqli_br_s = lane_nosqli.nosqli_login(base + "/nosqli-br-safe", send_as="form")
    sx_v = lane_storedxss.stored_xss(base + "/comment-vuln", base + "/comments-vuln", param="comment")
    sx_s = lane_storedxss.stored_xss(base + "/comment-safe", base + "/comments-safe", param="comment")
    csrf_v = lane_csrf.csrf_probe(base + "/csrf-vuln", bench_vuln.CSRF_COOKIE, bench_vuln.CSRF_TOKEN)
    csrf_s = lane_csrf.csrf_probe(base + "/csrf-safe", bench_vuln.CSRF_COOKIE, bench_vuln.CSRF_TOKEN)
    # mass-assignment: scrive su /profile-* e rilegge lo stato dallo stesso endpoint (GET)
    ma_v = lane_massassign.mass_assign(base + "/profile-vuln", read_url=base + "/profile-vuln", field="role")
    ma_s = lane_massassign.mass_assign(base + "/profile-safe", read_url=base + "/profile-safe", field="role")
    ssrf_v = lane_ssrf.ssrf(base + "/ssrf-vuln", param="url")
    ssrf_s = lane_ssrf.ssrf(base + "/ssrf-safe", param="url")
    trav_v = lane_traversal.traversal_probe(base + "/download-vuln", param="file", send_as="query")
    trav_s = lane_traversal.traversal_probe(base + "/download-safe", param="file", send_as="query")
    # Traversal bersaglio Windows (win.ini) + troncatura NUL-byte legacy
    trav_w_v = lane_traversal.traversal_probe(base + "/wdownload-vuln", param="file", send_as="query")
    trav_w_s = lane_traversal.traversal_probe(base + "/wdownload-safe", param="file", send_as="query")
    # Traversal via php://filter (LFI → source disclosure): wrapper che svela la sorgente PHP
    trav_php_v = lane_traversal.traversal_probe(base + "/lfi-vuln", param="page", send_as="query")
    trav_php_s = lane_traversal.traversal_probe(base + "/lfi-safe", param="page", send_as="query")
    # Traversal via data:// wrapper (LFI → RCE): stream scelto dal client, INCLUSO ed
    # ESEGUITO. Endpoint dedicato (/rce-data-*) senza php://filter → il verdetto
    # VULNERABILE è attribuibile al solo data:// (firma: il prodotto PHP calcolato).
    trav_data_v = lane_traversal.traversal_probe(base + "/rce-data-vuln", param="page", send_as="query")
    trav_data_s = lane_traversal.traversal_probe(base + "/rce-data-safe", param="page", send_as="query")
    # Auth-XSS: reflected XSS dietro l'AUTENTICAZIONE. La sessione (cookie valido)
    # instradata in core.probe sblocca la pagina riservata; senza di essa la lane
    # vedrebbe solo il login wall (provato dal session self-check). Stessa lane
    # `xss`, superficie di detection distinta (loggata) → +2, come IDOR/IDOR-token.
    _axss_sess = core.make_session(cookie=f"sess={bench_vuln.SESSION_VALID}")
    axss_v = lane_xss.xss_reflected(base + "/axss-vuln", param="q", send_as="query", session=_axss_sess)
    axss_s = lane_xss.xss_reflected(base + "/axss-safe", param="q", send_as="query", session=_axss_sess)
    # Auth-SQLi: SQL injection dietro l'AUTENTICAZIONE. La sessione instradata in
    # core.probe (lane_attack) sblocca la ricerca riservata; senza, la lane
    # vedrebbe solo il login wall (corpo costante) e TACEREBBE. Stessa lane `sqli`,
    # superficie di detection distinta (loggata) → +2, come Auth-XSS. È la prova
    # end-to-end che la sessione estesa alle lane attive raggiunge davvero la
    # superficie loggata (le altre lane wired — ssti/traversal/nosqli/cors/ssrf —
    # sono coperte dal SESSION-THREADING self-check, che prova l'inoltro in probe).
    _asqli_sess = core.make_session(cookie=f"sess={bench_vuln.SESSION_VALID}")
    asqli_v = lane_attack.sqli_login(base + "/asqli-vuln", field="username", send_as="json", session=_asqli_sess)
    asqli_s = lane_attack.sqli_login(base + "/asqli-safe", field="username", send_as="json", session=_asqli_sess)
    # Auth-StoredXSS: stored/persistent XSS DIETRO L'AUTENTICAZIONE. La sessione è
    # instradata in ENTRAMBE le probe della lane (scrittura + lettura) → sblocca
    # la bacheca riservata; senza, la scrittura è rifiutata (401) e la lettura è il
    # login wall → il canary non riemerge e la lane TACEREBBE (no FP). Stessa lane
    # `stored-xss`, superficie di detection distinta (loggata) → +2, come Auth-XSS/
    # Auth-SQLi. Prova end-to-end che la sessione estesa a stored-xss raggiunge la
    # superficie loggata (redirect/race coperte dal SESSION-THREADING self-check).
    _asx_sess = core.make_session(cookie=f"sess={bench_vuln.SESSION_VALID}")
    asx_v = lane_storedxss.stored_xss(base + "/acomment-vuln", base + "/acomments-vuln", param="comment", session=_asx_sess)
    asx_s = lane_storedxss.stored_xss(base + "/acomment-safe", base + "/acomments-safe", param="comment", session=_asx_sess)
    # TLS/transport (dominio nuovo): il bersaglio è un server TLS locale (non HTTP),
    # vuln = cert SCADUTO (8100), safe = cert VALIDO (8101), firmati dalla CA di test
    # (bench_certs/ca-bundle.crt passata come cafile) → l'unica differenza di verifica
    # è la scadenza. `_worst` riduce l'audit [tls:cert, tls:protocol] a un verdetto.
    _tls_ca = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_certs", "ca-bundle.crt")
    tls_v = lane_tls._worst(lane_tls.tls_audit("127.0.0.1:8100", cafile=_tls_ca))
    tls_s = lane_tls._worst(lane_tls.tls_audit("127.0.0.1:8101", cafile=_tls_ca))
    # GraphQL (dominio nuovo lato HTTP): tre debolezze di configurazione tipiche
    # (introspection esposta / field suggestion / query batching). `_worst` riduce
    # l'audit a un verdetto; il vuln espone tutte e tre, il safe nessuna.
    gql_v = lane_graphql._worst(lane_graphql.graphql_audit(base + "/graphql-vuln"))
    gql_s = lane_graphql._worst(lane_graphql.graphql_audit(base + "/graphql-safe"))
    # GraphQL transport GET → CSRF da mutation: il vuln esegue `mutation{__typename}`
    # inviata via GET (forgeable cross-site), il safe la vieta (405, solo POST) ma
    # ammette le query read-only su GET. Sonda senza effetti (meta-campo __typename).
    gqlget_v = lane_graphql._get_transport_check(base + "/graphql-vuln")
    gqlget_s = lane_graphql._get_transport_check(base + "/graphql-safe")
    # GraphQL transport FORM POST → CSRF da mutation: il vuln esegue
    # `mutation{__typename}` inviata come `application/x-www-form-urlencoded`
    # (content-type CORS-semplice → forgeable via `<form>` senza preflight né token),
    # il safe esige application/json per le mutation (415 sul form → preflight CORS).
    # Sonda senza effetti (meta-campo __typename), gemella del transport GET.
    gqlform_v = lane_graphql._form_transport_check(base + "/graphql-vuln")
    gqlform_s = lane_graphql._form_transport_check(base + "/graphql-safe")
    # XXE (dominio nuovo lato parsing XML): il vuln parsa il corpo XML con le
    # entità esterne ABILITATE → un'entità SYSTEM 'file://' è risolta e il
    # contenuto di /etc/passwd entra nella risposta (firma `root:…:0:0:`); il safe
    # disabilita l'external-entity processing (la difesa canonica) → nessuna firma.
    # Prova OGGETTIVA via firma del file (come traversal), non la riflessione:
    # inviamo `&xxe;` (un riferimento), mai il contenuto → l'eco non la produce.
    xxe_v = lane_xxe.xxe_probe(base + "/xxe-vuln")
    xxe_s = lane_xxe.xxe_probe(base + "/xxe-safe")
    findings = [sqli_v, sqli_s, sqli_tb_v, sqli_tb_s, xss_v, xss_s, auth_v, auth_s,
                idor_v, idor_s, idor_br_v, idor_br_s, dom_v, dom_s, race_v, race_s, red_v, red_s,
                crlf_v, crlf_s,
                cors_v, cors_s, cors_pf_v, cors_pf_s, oapi_v, oapi_s, oapi_auth_v, oapi_auth_s,
                oapi_idor_v, oapi_idor_s, oapi_comp_v, oapi_comp_s, oapi_nosqli_v, oapi_nosqli_s,
                oapi_ssti_v, oapi_ssti_s, oapi_trav_v, oapi_trav_s, oapi_red_v, oapi_red_s,
                oapi_ssrf_v, oapi_ssrf_s, oapi_crlf_v, oapi_crlf_s, oapi_jwt_v, oapi_jwt_s,
                jwt_v, jwt_s, ssti_v, ssti_s,
                nosqli_v, nosqli_s, nosqli_br_v, nosqli_br_s, sx_v, sx_s, csrf_v, csrf_s, ma_v, ma_s, ssrf_v, ssrf_s,
                trav_v, trav_s, trav_w_v, trav_w_s, trav_php_v, trav_php_s,
                trav_data_v, trav_data_s,
                axss_v, axss_s, asqli_v, asqli_s, asx_v, asx_s, tls_v, tls_s, gql_v, gql_s,
                gqlget_v, gqlget_s, gqlform_v, gqlform_s, xxe_v, xxe_s]

    rep_ok, rep_detail = _report_selfcheck(findings)       # export referto (non-lane)
    gate_ok, gate_detail = _failon_selfcheck()             # gate CI --fail-on (non-lane)
    gaten_ok, gaten_detail = _failonnew_selfcheck()        # gate CI --fail-on-new (non-lane)
    ss_ok, ss_detail = _samesite_selfcheck(base)           # difesa CSRF via SameSite (check passivo, non-lane)
    hsts_ok, hsts_detail = _hsts_selfcheck(base)           # difesa HSTS via max-age (check passivo, non-lane)
    csp_ok, csp_detail = _csp_selfcheck(base)              # difesa XSS via CSP value-aware (check passivo, non-lane)
    xcto_ok, xcto_detail = _xcto_selfcheck(base)           # difesa MIME-sniffing via X-Content-Type-Options value-aware (check passivo, non-lane)
    xfo_ok, xfo_detail = _xfo_selfcheck(base)              # difesa anti-clickjacking via X-Frame-Options value-aware (check passivo, non-lane)
    owasp_ok, owasp_detail = _owasp_selfcheck(findings, base)  # tag categoria OWASP 2021 (tassonomia, non-lane)
    adv_ok, adv_detail = _adversarial_selfcheck(base)      # banco avversariale (3ª faccia, cancello anti-FP, non-lane)
    bgate_ok, bgate_detail = _benchgate_selfcheck()        # cancello verde→exit-code (core.bench_green, non-lane)
    sess_ok, sess_detail = _session_selfcheck(base)        # sessione → superficie loggata (core.probe, non-lane)
    thr_ok, thr_detail = _session_threading_selfcheck(base) # ogni lane attiva inoltra la sessione in probe (non-lane)
    hist_ok, hist_detail = _history_selfcheck()            # andamento nel tempo (findings-DB, read-only, non-lane)
    spark_ok, spark_detail = _sparkline_selfcheck()        # sparkline SVG dell'andamento (report HTML di history, non-lane)
    fleet_ok, fleet_detail = _fleet_selfcheck()            # parco macchine multi-bersaglio (history senza target, non-lane)
    sarif_ok, sarif_detail = _sarif_selfcheck()            # export SARIF 2.1.0 (GitHub code scanning, non-lane)
    junit_ok, junit_detail = _junit_selfcheck()            # export JUnit XML (report CI, non-lane)
    self_ok = (rep_ok and gate_ok and gaten_ok and ss_ok and hsts_ok and csp_ok and xcto_ok and xfo_ok and owasp_ok and adv_ok
               and bgate_ok and sess_ok and thr_ok and hist_ok and spark_ok
               and fleet_ok and sarif_ok and junit_ok)

    def score(tp_f, tn_f):                       # vero positivo + vero negativo
        return int("VULNERABILE" in tp_f["verdict"]) + int("VULNERABILE" not in tn_f["verdict"])
    (s_sqli, s_sqli_tb, s_xss, s_auth, s_idor, s_idor_br, s_dom, s_race, s_red, s_crlf,
     s_cors, s_cors_pf, s_oapi, s_oapi_auth, s_oapi_idor, s_oapi_comp, s_oapi_nosqli, s_oapi_ssti, s_oapi_trav, s_oapi_red, s_oapi_ssrf, s_oapi_crlf, s_oapi_jwt, s_jwt, s_ssti, s_nosqli, s_nosqli_br, s_sx, s_csrf, s_ma, s_ssrf,
     s_trav, s_trav_w, s_trav_php, s_trav_data, s_axss, s_asqli, s_asx, s_tls, s_gql, s_gqlget, s_gqlform, s_xxe) = (
        score(sqli_v, sqli_s), score(sqli_tb_v, sqli_tb_s), score(xss_v, xss_s),
        score(auth_v, auth_s), score(idor_v, idor_s), score(idor_br_v, idor_br_s),
        score(dom_v, dom_s), score(race_v, race_s), score(red_v, red_s), score(crlf_v, crlf_s),
        score(cors_v, cors_s), score(cors_pf_v, cors_pf_s),
        score(oapi_v, oapi_s), score(oapi_auth_v, oapi_auth_s), score(oapi_idor_v, oapi_idor_s),
        score(oapi_comp_v, oapi_comp_s), score(oapi_nosqli_v, oapi_nosqli_s), score(oapi_ssti_v, oapi_ssti_s),
        score(oapi_trav_v, oapi_trav_s), score(oapi_red_v, oapi_red_s),
        score(oapi_ssrf_v, oapi_ssrf_s), score(oapi_crlf_v, oapi_crlf_s), score(oapi_jwt_v, oapi_jwt_s),
        score(jwt_v, jwt_s), score(ssti_v, ssti_s),
        score(nosqli_v, nosqli_s), score(nosqli_br_v, nosqli_br_s), score(sx_v, sx_s), score(csrf_v, csrf_s),
        score(ma_v, ma_s), score(ssrf_v, ssrf_s), score(trav_v, trav_s),
        score(trav_w_v, trav_w_s), score(trav_php_v, trav_php_s), score(trav_data_v, trav_data_s),
        score(axss_v, axss_s),
        score(asqli_v, asqli_s), score(asx_v, asx_s), score(tls_v, tls_s), score(gql_v, gql_s),
        score(gqlget_v, gqlget_s), score(gqlform_v, gqlform_s), score(xxe_v, xxe_s))

    # Cancello verde/rosso: ogni lane NON esente deve essere a 2/2 E ogni
    # self-check deve passare. `dom-xss` è ESENTE (Playwright, può mancare in
    # cloud/CI) → escluso dal cancello. Determina l'exit-code di `aries bench`
    # (0 verde, 1 rosso) così un GitHub Action blocca i commit che rompono il tool.
    gated_scores = [s_sqli, s_sqli_tb, s_xss, s_auth, s_idor, s_idor_br, s_race,
                    s_red, s_crlf, s_cors, s_cors_pf, s_oapi, s_oapi_auth, s_oapi_idor, s_oapi_comp, s_oapi_nosqli, s_oapi_ssti, s_oapi_trav, s_oapi_red, s_oapi_ssrf, s_oapi_crlf, s_oapi_jwt, s_jwt, s_ssti, s_nosqli, s_nosqli_br,
                    s_sx, s_csrf, s_ma, s_ssrf, s_trav, s_trav_w, s_trav_php, s_trav_data,
        s_axss, s_asqli, s_asx, s_tls, s_gql, s_gqlget, s_gqlform, s_xxe]
    green = core.bench_green(gated_scores, self_ok)
    esito = "VERDE (exit 0)" if green else "ROSSO (exit 1)"

    if a.json:
        print(core.to_json("benchmark lane attive (fixture locale)", findings))
        print(f"REPORT self-check: {'OK' if rep_ok else 'FAIL'} — {rep_detail}", file=sys.stderr)
        print(f"FAIL-ON self-check: {'OK' if gate_ok else 'FAIL'} — {gate_detail}", file=sys.stderr)
        print(f"FAIL-ON-NEW self-check: {'OK' if gaten_ok else 'FAIL'} — {gaten_detail}", file=sys.stderr)
        print(f"SAMESITE self-check: {'OK' if ss_ok else 'FAIL'} — {ss_detail}", file=sys.stderr)
        print(f"HSTS self-check: {'OK' if hsts_ok else 'FAIL'} — {hsts_detail}", file=sys.stderr)
        print(f"CSP self-check: {'OK' if csp_ok else 'FAIL'} — {csp_detail}", file=sys.stderr)
        print(f"XCTO self-check: {'OK' if xcto_ok else 'FAIL'} — {xcto_detail}", file=sys.stderr)
        print(f"XFO self-check: {'OK' if xfo_ok else 'FAIL'} — {xfo_detail}", file=sys.stderr)
        print(f"OWASP self-check: {'OK' if owasp_ok else 'FAIL'} — {owasp_detail}", file=sys.stderr)
        print(f"ADVERSARIAL self-check: {'OK' if adv_ok else 'FAIL'} — {adv_detail}", file=sys.stderr)
        print(f"BENCH-GATE self-check: {'OK' if bgate_ok else 'FAIL'} — {bgate_detail}", file=sys.stderr)
        print(f"SESSION self-check: {'OK' if sess_ok else 'FAIL'} — {sess_detail}", file=sys.stderr)
        print(f"SESSION-THREADING self-check: {'OK' if thr_ok else 'FAIL'} — {thr_detail}", file=sys.stderr)
        print(f"HISTORY self-check: {'OK' if hist_ok else 'FAIL'} — {hist_detail}", file=sys.stderr)
        print(f"SPARKLINE self-check: {'OK' if spark_ok else 'FAIL'} — {spark_detail}", file=sys.stderr)
        print(f"FLEET self-check: {'OK' if fleet_ok else 'FAIL'} — {fleet_detail}", file=sys.stderr)
        print(f"SARIF self-check: {'OK' if sarif_ok else 'FAIL'} — {sarif_detail}", file=sys.stderr)
        print(f"JUNIT self-check: {'OK' if junit_ok else 'FAIL'} — {junit_detail}", file=sys.stderr)
        print(f"BENCH esito: {esito} (dom-xss esente)", file=sys.stderr)
        sys.exit(0 if green else 1)

    print(core.to_text("benchmark lane attive (fixture locale)", findings))
    print("\n== PUNTEGGIO lane attive (vuln rilevata + safe non segnalata) ==")
    print(f"  SQLi        : {s_sqli}/2")
    print(f"  SQLi-time   : {s_sqli_tb}/2")
    print(f"  XSS         : {s_xss}/2")
    print(f"  Auth        : {s_auth}/2")
    print(f"  IDOR        : {s_idor}/2")
    print(f"  IDOR-token  : {s_idor_br}/2")
    print(f"  DOM-XSS     : {s_dom}/2")
    print(f"  Race        : {s_race}/2")
    print(f"  Redirect    : {s_red}/2")
    print(f"  CRLF        : {s_crlf}/2")
    print(f"  CORS        : {s_cors}/2")
    print(f"  CORS-preflt : {s_cors_pf}/2")
    print(f"  OpenAPI     : {s_oapi}/2")
    print(f"  OpenAPI-auth: {s_oapi_auth}/2")
    print(f"  OpenAPI-idor: {s_oapi_idor}/2")
    print(f"  OpenAPI-compose: {s_oapi_comp}/2")
    print(f"  OpenAPI-nosqli: {s_oapi_nosqli}/2")
    print(f"  OpenAPI-ssti: {s_oapi_ssti}/2")
    print(f"  OpenAPI-trav: {s_oapi_trav}/2")
    print(f"  OpenAPI-redir: {s_oapi_red}/2")
    print(f"  OpenAPI-ssrf: {s_oapi_ssrf}/2")
    print(f"  OpenAPI-crlf: {s_oapi_crlf}/2")
    print(f"  OpenAPI-jwt : {s_oapi_jwt}/2")
    print(f"  JWT         : {s_jwt}/2")
    print(f"  SSTI        : {s_ssti}/2")
    print(f"  NoSQLi      : {s_nosqli}/2")
    print(f"  NoSQLi-bracket: {s_nosqli_br}/2")
    print(f"  Stored-XSS  : {s_sx}/2")
    print(f"  CSRF        : {s_csrf}/2")
    print(f"  Mass-assign : {s_ma}/2")
    print(f"  SSRF        : {s_ssrf}/2")
    print(f"  Traversal   : {s_trav}/2")
    print(f"  Traversal-win: {s_trav_w}/2")
    print(f"  Traversal-php: {s_trav_php}/2")
    print(f"  Traversal-data: {s_trav_data}/2")
    print(f"  Auth-XSS    : {s_axss}/2")
    print(f"  Auth-SQLi   : {s_asqli}/2")
    print(f"  Auth-StoredXSS: {s_asx}/2")
    print(f"  TLS         : {s_tls}/2")
    print(f"  GraphQL     : {s_gql}/2")
    print(f"  GraphQL-get : {s_gqlget}/2")
    print(f"  GraphQL-form: {s_gqlform}/2")
    print(f"  XXE         : {s_xxe}/2")
    print(f"  TOTALE      : {s_sqli + s_sqli_tb + s_xss + s_auth + s_idor + s_idor_br + s_dom + s_race + s_red + s_cors + s_cors_pf + s_oapi + s_oapi_auth + s_oapi_idor + s_oapi_comp + s_oapi_nosqli + s_oapi_ssti + s_oapi_trav + s_oapi_red + s_oapi_ssrf + s_oapi_crlf + s_oapi_jwt + s_jwt + s_ssti + s_nosqli + s_nosqli_br + s_sx + s_csrf + s_ma + s_ssrf + s_trav + s_trav_w + s_trav_php + s_trav_data + s_axss + s_asqli + s_asx + s_tls + s_gql + s_gqlget + s_gqlform + s_xxe}/84")
    print(f"\n== REPORT self-check (export referto, non-lane) ==\n  "
          f"{'OK' if rep_ok else 'FAIL'} — {rep_detail}")
    print(f"\n== FAIL-ON self-check (gate CI --fail-on, non-lane) ==\n  "
          f"{'OK' if gate_ok else 'FAIL'} — {gate_detail}")
    print(f"\n== FAIL-ON-NEW self-check (gate CI --fail-on-new, non-lane) ==\n  "
          f"{'OK' if gaten_ok else 'FAIL'} — {gaten_detail}")
    print(f"\n== SAMESITE self-check (difesa CSRF via SameSite in `check`, non-lane) ==\n  "
          f"{'OK' if ss_ok else 'FAIL'} — {ss_detail}")
    print(f"\n== HSTS self-check (difesa HSTS via max-age in `check`, non-lane) ==\n  "
          f"{'OK' if hsts_ok else 'FAIL'} — {hsts_detail}")
    print(f"\n== CSP self-check (difesa XSS via CSP value-aware in `check`, non-lane) ==\n  "
          f"{'OK' if csp_ok else 'FAIL'} — {csp_detail}")
    print(f"\n== XCTO self-check (difesa MIME-sniffing via X-Content-Type-Options value-aware in `check`, non-lane) ==\n  "
          f"{'OK' if xcto_ok else 'FAIL'} — {xcto_detail}")
    print(f"\n== XFO self-check (difesa anti-clickjacking via X-Frame-Options value-aware in `check`, non-lane) ==\n  "
          f"{'OK' if xfo_ok else 'FAIL'} — {xfo_detail}")
    print(f"\n== OWASP self-check (tag categoria OWASP Top 10 2021, non-lane) ==\n  "
          f"{'OK' if owasp_ok else 'FAIL'} — {owasp_detail}")
    print(f"\n== ADVERSARIAL self-check (banco avversariale, 3ª faccia anti-FP, non-lane) ==\n  "
          f"{'OK' if adv_ok else 'FAIL'} — {adv_detail}")
    print(f"\n== BENCH-GATE self-check (cancello verde→exit-code, non-lane) ==\n  "
          f"{'OK' if bgate_ok else 'FAIL'} — {bgate_detail}")
    print(f"\n== SESSION self-check (sessione → superficie loggata in core.probe, non-lane) ==\n  "
          f"{'OK' if sess_ok else 'FAIL'} — {sess_detail}")
    print(f"\n== SESSION-THREADING self-check (ogni lane attiva inoltra la sessione in probe, non-lane) ==\n  "
          f"{'OK' if thr_ok else 'FAIL'} — {thr_detail}")
    print(f"\n== HISTORY self-check (andamento nel tempo dalla findings-DB, read-only, non-lane) ==\n  "
          f"{'OK' if hist_ok else 'FAIL'} — {hist_detail}")
    print(f"\n== SPARKLINE self-check (andamento grafico inline nel report HTML di history, non-lane) ==\n  "
          f"{'OK' if spark_ok else 'FAIL'} — {spark_detail}")
    print(f"\n== FLEET self-check (parco macchine multi-bersaglio, `history` senza target, read-only, non-lane) ==\n  "
          f"{'OK' if fleet_ok else 'FAIL'} — {fleet_detail}")
    print(f"\n== SARIF self-check (export SARIF 2.1.0 per GitHub code scanning, non-lane) ==\n  "
          f"{'OK' if sarif_ok else 'FAIL'} — {sarif_detail}")
    print(f"\n== JUNIT self-check (export JUnit XML per i runner CI, non-lane) ==\n  "
          f"{'OK' if junit_ok else 'FAIL'} — {junit_detail}")
    print(f"\n== ESITO BENCH ==\n  {esito} — dom-xss esente (Playwright). "
          f"Un GitHub Action blocca i commit che rompono il tool.")
    sys.exit(0 if green else 1)


def main():
    p = argparse.ArgumentParser(prog="aries", description="ARIES — security testing locale")
    sub = p.add_subparsers(dest="cmd", required=True)

    def _add_session_args(parser):
        """Flag di SESSIONE comuni (--cookie/--token/--header): testano la
        superficie LOGGATA instradando le credenziali in core.probe."""
        parser.add_argument("--cookie", default=None,
                            help="header Cookie della sessione autenticata (es. 'sid=…')")
        parser.add_argument("--token", default=None,
                            help="token per Authorization: Bearer (API a token)")
        parser.add_argument("--header", action="append", default=None, metavar="'K: V'",
                            help="header custom di sessione, ripetibile (es. --header 'X-Api-Key: …')")

    pc = sub.add_parser("check", help="igiene web deterministica (sola lettura)")
    pc.add_argument("url")
    _add_session_args(pc)
    pc.add_argument("--json", action="store_true")
    pc.set_defaults(fn=cmd_check)

    pf = sub.add_parser("fuzz", help="fuzzing di un parser (discovery)")
    pf.add_argument("target", nargs="?")
    pf.add_argument("--json", action="store_true")
    pf.set_defaults(fn=cmd_fuzz)

    pa = sub.add_parser("attack", help="test attivi SQLi (manda payload)")
    pa.add_argument("url")
    pa.add_argument("--field", default="username", help="campo da iniettare")
    pa.add_argument("--as", dest="send_as", default="json", choices=["json", "form", "query"])
    _add_session_args(pa)
    pa.add_argument("--json", action="store_true")
    pa.set_defaults(fn=cmd_attack)

    pid = sub.add_parser("idor", help="test broken access control / IDOR (ATTIVO)")
    pid.add_argument("url", help="URL della risorsa: id in query (?id=) oppure placeholder {id} nel path (es. .../basket/{id})")
    pid.add_argument("--param", default="id", help="nome del parametro id (query mode)")
    pid.add_argument("--owned", default="1", help="id di una TUA risorsa")
    pid.add_argument("--other", default="2", help="id di una risorsa ALTRUI")
    pid.add_argument("--id-header", dest="id_header", default="X-User", help="header che porta l'identità")
    pid.add_argument("--identity", default="1", help="valore della tua identità")
    pid.add_argument("--token", default=None, help="JWT per Authorization: Bearer (sostituisce l'header identità)")
    pid.add_argument("--json", action="store_true")
    pid.set_defaults(fn=cmd_idor)

    pau = sub.add_parser("auth", help="test runtime rate-limit/lockout del login (ATTIVO, username finto)")
    pau.add_argument("url")
    pau.add_argument("--field", default="username")
    pau.add_argument("--as", dest="send_as", default="json", choices=["json", "form", "query"])
    pau.add_argument("--attempts", type=int, default=8)
    pau.add_argument("--json", action="store_true")
    pau.set_defaults(fn=cmd_auth)

    pj = sub.add_parser("jwt", help="debolezze JWT: alg=none, chiave HS debole, exp ignorata (ATTIVO)")
    pj.add_argument("url", help="endpoint protetto che accetta il token (Authorization: Bearer)")
    pj.add_argument("token", help="un JWT VALIDO (quello dell'utente legittimo)")
    pj.add_argument("--wordlist", default=None, help="wordlist chiavi HS (default: wordlists/jwt-secrets.txt)")
    pj.add_argument("--json", action="store_true")
    pj.set_defaults(fn=cmd_jwt)

    prc = sub.add_parser("race", help="test race condition / TOCTOU — richieste concorrenti (ATTIVO)")
    prc.add_argument("url", help="endpoint di un'operazione 'una volta sola' (es. riscatto)")
    prc.add_argument("--method", default="POST")
    prc.add_argument("--concurrency", type=int, default=20)
    prc.add_argument("--body", default=None, help="corpo della richiesta (opzionale)")
    _add_session_args(prc)
    prc.add_argument("--json", action="store_true")
    prc.set_defaults(fn=cmd_race)

    prr = sub.add_parser("redirect", help="test open-redirect: il param di redirect porta verso un host esterno? (ATTIVO)")
    prr.add_argument("url", help="endpoint di redirect (es. http://host/redirect)")
    prr.add_argument("--param", default="to", help="nome del parametro di redirect (default: to)")
    prr.add_argument("--allowed", default=None, help="un URL consentito dall'app → abilita i payload bypass-allowlist")
    _add_session_args(prr)
    prr.add_argument("--json", action="store_true")
    prr.set_defaults(fn=cmd_redirect)

    pcr = sub.add_parser("crlf", help="CRLF / HTTP response header injection: un param scrive CR-LF grezzo in un header → split (ATTIVO)")
    pcr.add_argument("url", help="endpoint il cui parametro finisce in un header di risposta (es. http://host/redirect)")
    pcr.add_argument("--param", default="to", help="nome del parametro iniettato (default: to)")
    _add_session_args(pcr)
    pcr.add_argument("--json", action="store_true")
    pcr.set_defaults(fn=cmd_crlf)

    pco = sub.add_parser("cors", help="misconfigurazione CORS: Origin arbitrario riflesso + credenziali (ATTIVO)")
    pco.add_argument("url", help="endpoint che risponde a richieste cross-origin (es. un'API con sessione)")
    _add_session_args(pco)
    pco.add_argument("--json", action="store_true")
    pco.set_defaults(fn=cmd_cors)

    pxe = sub.add_parser("xxe", help="XXE: un'API che parsa XML risolve le entità esterne (file:///etc/passwd)? (ATTIVO)")
    pxe.add_argument("url", help="endpoint che accetta e parsa un corpo XML (POST)")
    _add_session_args(pxe)
    pxe.add_argument("--json", action="store_true")
    pxe.set_defaults(fn=cmd_xxe)

    pdx = sub.add_parser("dom-xss", help="DOM-XSS lato client con browser headless (ATTIVO; URL con token PAYLOAD)")
    pdx.add_argument("url", help="URL contenente il token letterale PAYLOAD dove iniettare")
    pdx.add_argument("--json", action="store_true")
    pdx.set_defaults(fn=cmd_dom_xss)

    pst = sub.add_parser("ssti", help="Server-Side Template Injection: espressione aritmetica valutata dal template (ATTIVO)")
    pst.add_argument("url")
    pst.add_argument("--param", default="q", help="parametro da iniettare")
    pst.add_argument("--as", dest="send_as", default="query", choices=["query", "form", "json"])
    _add_session_args(pst)
    pst.add_argument("--json", action="store_true")
    pst.set_defaults(fn=cmd_ssti)

    pnq = sub.add_parser("nosqli", help="NoSQL operator injection nel login (bypass auth via $ne/$in; JSON o bracket-notation form) — ATTIVO")
    pnq.add_argument("url", help="endpoint di login che accetta un body JSON o form")
    pnq.add_argument("--user-field", dest="user_field", default="username", help="nome del campo username")
    pnq.add_argument("--pass-field", dest="pass_field", default="password", help="nome del campo password")
    pnq.add_argument("--user", default="admin", help="username noto per la baseline")
    pnq.add_argument("--as", dest="send_as", default="json", choices=["json", "form"],
                     help="transport: json (operatore nel body JSON) o form (bracket-notation campo[$op]=)")
    _add_session_args(pnq)
    pnq.add_argument("--json", action="store_true")
    pnq.set_defaults(fn=cmd_nosqli)

    px = sub.add_parser("xss", help="test attivo reflected XSS lato server (manda payload)")
    px.add_argument("url")
    px.add_argument("--param", default="q", help="parametro da iniettare")
    px.add_argument("--as", dest="send_as", default="query", choices=["query", "form", "json"])
    _add_session_args(px)
    px.add_argument("--json", action="store_true")
    px.set_defaults(fn=cmd_xss)

    psx = sub.add_parser("stored-xss", help="stored/persistent XSS: il payload scritto su un endpoint riemerge non-escapato da un altro (ATTIVO; due URL)")
    psx.add_argument("write_url", help="endpoint di SCRITTURA (dove si invia il payload, es. POST /commento)")
    psx.add_argument("read_url", help="endpoint di LETTURA (dove riemerge, es. GET /commenti)")
    psx.add_argument("--param", default="comment", help="campo che porta il payload nella scrittura")
    psx.add_argument("--as", dest="send_as", default="json", choices=["json", "form", "query"])
    _add_session_args(psx)
    psx.add_argument("--json", action="store_true")
    psx.set_defaults(fn=cmd_stored_xss)

    pcf = sub.add_parser("csrf", help="CSRF: il token anti-CSRF è validato su un endpoint che cambia stato? (ATTIVO)")
    pcf.add_argument("url", help="endpoint di scrittura (POST) autenticato dalla sessione")
    pcf.add_argument("--cookie", default="", help="valore dell'header Cookie (la sessione autenticata)")
    pcf.add_argument("--token", default="", help="un token anti-CSRF VALIDO (quello della pagina legittima)")
    pcf.add_argument("--token-field", dest="token_field", default="csrf_token", help="nome del campo che porta il token CSRF")
    pcf.add_argument("--as", dest="send_as", default="form", choices=["form", "json"])
    pcf.add_argument("--data", default=None, help="campi extra del corpo in forma 'k=v&k2=v2' (merge, costanti tra le richieste)")
    pcf.add_argument("--json", action="store_true")
    pcf.set_defaults(fn=cmd_csrf)

    pma = sub.add_parser("mass-assign", help="mass assignment: il client può impostare un campo server-controlled (es. role)? (ATTIVO)")
    pma.add_argument("write_url", help="endpoint di scrittura (POST) che aggiorna/crea la risorsa")
    pma.add_argument("--read-url", dest="read_url", default=None,
                     help="endpoint GET che rende lo stato (default: il corpo della risposta di scrittura)")
    pma.add_argument("--field", default="role", help="campo privilegiato da provare (es. role, isAdmin, verified)")
    pma.add_argument("--value", default=None, help="valore da iniettare nel campo (default: un nonce unico; usa un valore reale se il campo è enum-validato)")
    pma.add_argument("--data", default=None, help="campi legittimi del corpo in forma 'k=v&k2=v2' (merge)")
    pma.add_argument("--as", dest="send_as", default="json", choices=["json", "form"])
    pma.add_argument("--cookie", default=None, help="valore dell'header Cookie (se l'endpoint è autenticato)")
    pma.add_argument("--json", action="store_true")
    pma.set_defaults(fn=cmd_massassign)

    psr = sub.add_parser("ssrf", help="SSRF: il server segue un URL scelto dal client? (canary locale out-of-band) — ATTIVO")
    psr.add_argument("url", help="endpoint che accetta un URL (webhook/fetcher/anteprima), es. http://host/fetch")
    psr.add_argument("--param", default="url", help="nome del parametro che porta l'URL (default: url)")
    psr.add_argument("--as", dest="send_as", default="query", choices=["query", "form", "json"])
    psr.add_argument("--method", default=None, help="metodo HTTP (default: GET per query, POST per form/json)")
    _add_session_args(psr)
    psr.add_argument("--json", action="store_true")
    psr.set_defaults(fn=cmd_ssrf)

    ptr = sub.add_parser("traversal", help="path traversal / LFI: un parametro di file esce dalla radice e legge file di sistema? (ATTIVO)")
    ptr.add_argument("url", help="endpoint che serve un file da un parametro, es. http://host/download?file=X")
    ptr.add_argument("--param", default="file", help="nome del parametro che porta il nome del file (default: file)")
    ptr.add_argument("--as", dest="send_as", default="query", choices=["query", "form", "json"])
    ptr.add_argument("--method", default="GET", help="metodo HTTP (default: GET)")
    _add_session_args(ptr)
    ptr.add_argument("--json", action="store_true")
    ptr.set_defaults(fn=cmd_traversal)

    ptl = sub.add_parser("tls", help="igiene TLS/transport: certificato scaduto/non valido, protocollo deprecato (ATTIVO; solo handshake)")
    ptl.add_argument("target", help="host[:port] o URL https, es. 127.0.0.1:8443 o https://host (porta default 443)")
    ptl.add_argument("--cafile", default=None,
                     help="bundle di CA fidate (PEM) per verificare una CA interna/self-signed; default: CA di sistema")
    ptl.add_argument("--json", action="store_true")
    ptl.set_defaults(fn=cmd_tls)

    pgq = sub.add_parser("graphql", help="GraphQL: introspection esposta, field suggestion, query batching, CSRF da mutation via GET/form (ATTIVO)")
    pgq.add_argument("url", help="endpoint GraphQL (POST JSON), es. http://host/graphql")
    _add_session_args(pgq)
    pgq.add_argument("--json", action="store_true")
    pgq.set_defaults(fn=cmd_graphql)

    ps = sub.add_parser("secrets", help="cerca segreti esposti in un repo (orchestra gitleaks)")
    ps.add_argument("path")
    ps.add_argument("--history", action="store_true", help="scansiona anche la storia git")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(fn=cmd_secrets)

    pdi = sub.add_parser("discover", help="scopre endpoint/directory nascosti (orchestra ffuf) — ATTIVO")
    pdi.add_argument("url")
    pdi.add_argument("--wordlist", default=None, help="wordlist custom (default: wordlists/common.txt)")
    pdi.add_argument("--json", action="store_true")
    pdi.set_defaults(fn=cmd_discover)

    pn = sub.add_parser("nuclei", help="scanner web a template (orchestra nuclei) — ATTIVO")
    pn.add_argument("url")
    pn.add_argument("--severity", default="low,medium,high,critical", help="filtro severità nuclei")
    pn.add_argument("--json", action="store_true")
    pn.set_defaults(fn=cmd_nuclei)

    pd = sub.add_parser("deps", help="CVE note nelle dipendenze (orchestra trivy)")
    pd.add_argument("path")
    pd.add_argument("--json", action="store_true")
    pd.set_defaults(fn=cmd_deps)

    pg = sub.add_parser("sast", help="analisi statica del codice (orchestra semgrep)")
    pg.add_argument("path")
    pg.add_argument("--config", default="p/security-audit", help="ruleset semgrep")
    pg.add_argument("--json", action="store_true")
    pg.set_defaults(fn=cmd_sast)

    psc = sub.add_parser("scan", help="compone le lane + diff di regressione (sentinella)")
    psc.add_argument("target", help="URL (web) oppure path (codice)")
    psc.add_argument("--active", action="store_true", help="includi i test SQLi sugli URL (manda payload)")
    psc.add_argument("--field", default="username")
    psc.add_argument("--explain", action="store_true", help="aggiungi l'interpretazione di Qwen (LLM)")
    psc.add_argument("--report", default=None, metavar="FILE",
                     help="scrivi un referto condivisibile (estensione .md→Markdown, .html→HTML) con i PoC dentro")
    psc.add_argument("--fail-on", dest="fail_on", default=None,
                     choices=["crit", "high", "med", "low"],
                     help="gate CI ASSOLUTO: exit 1 se c'è almeno un finding a questa severità o più grave (es. --fail-on high)")
    psc.add_argument("--fail-on-new", dest="fail_on_new", default=None,
                     choices=["crit", "high", "med", "low"],
                     help="gate CI di REGRESSIONE: exit 1 solo se c'è un finding NUOVO (sentinella) a questa severità o più grave; il debito preesistente non conta (es. --fail-on-new high)")
    _add_session_args(psc)
    psc.add_argument("--json", action="store_true")
    psc.set_defaults(fn=cmd_scan)

    po = sub.add_parser("openapi", help="legge uno spec OpenAPI/Swagger e gira le lane sugli endpoint dichiarati (ATTIVO)")
    po.add_argument("spec", help="path dello spec (JSON; YAML se pyyaml presente)")
    po.add_argument("--base", default=None, help="base URL (override di servers/host nello spec)")
    po.add_argument("--lanes", default="check,xss,sqli,auth",
                    help="lane da girare, separate da virgola (check,xss,sqli,auth; nosqli/ssti/traversal/redirect/ssrf/crlf opt-in: nosqli sui login dichiarati, ssti sui parametri stringa riflessi, traversal sui parametri file-like, redirect sui parametri redirect-like in GET, ssrf sui parametri URL-like, crlf sui parametri header-sink in GET; idor e jwt richiedono un'identità/token, vedi sotto)")
    po.add_argument("--token", default=None,
                    help="JWT per Authorization: Bearer — identità per idor (GET con id nel path) e token per jwt (GET protette da schema bearer)")
    po.add_argument("--id-header", dest="id_header", default=None,
                    help="header che porta l'identità per idor (es. X-User), alternativa a --token")
    po.add_argument("--identity", default=None, help="valore dell'identità per idor (con --id-header)")
    po.add_argument("--owned", default="1", help="id di una TUA risorsa (idor)")
    po.add_argument("--other", default="2", help="id di una risorsa ALTRUI (idor)")
    po.add_argument("--json", action="store_true")
    po.set_defaults(fn=cmd_openapi)

    ph = sub.add_parser("history", help="andamento nel tempo di un bersaglio dalla findings-DB (sola lettura, nessun payload); senza TARGET → parco macchine multi-bersaglio")
    ph.add_argument("target", nargs="?", default=None,
                    help="lo stesso bersaglio (URL o path) passato a `scan`; "
                         "ometterlo → panoramica di TUTTI i bersagli (parco macchine)")
    ph.add_argument("--report", default=None, metavar="FILE",
                    help="scrivi la dashboard di andamento (estensione .md→Markdown, .html→HTML)")
    ph.add_argument("--json", action="store_true")
    ph.set_defaults(fn=cmd_history)

    pb = sub.add_parser("bench", help="valida la lane SQLi contro un fixture locale")
    pb.add_argument("--json", action="store_true")
    pb.set_defaults(fn=cmd_bench)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
