"""Lane DOM-XSS — XSS lato CLIENT (nel DOM), con un browser headless (Playwright).

La lane `xss` vede solo il reflected lato server (nel corpo HTTP). Il DOM-XSS
delle SPA succede NEL BROWSER (JS che mette input non fidato in innerHTML, ecc.):
non si vede dalla risposta. Qui carichiamo davvero la pagina in Chromium e
guardiamo se il payload ESEGUE.

Rilevamento (due segnali oggettivi):
  - il payload prova a settare `window.__aries_xss=1` → lo rileggiamo dopo il load
  - intercettiamo anche i dialog (alert/confirm/prompt) → se scatta, ha eseguito

Uso: passa un URL che contiene il token letterale `PAYLOAD`; la lane lo sostituisce
coi payload (nel query o nel fragment, ovunque tu l'abbia messo). ATTIVO, solo allowlist.
"""

from urllib.parse import quote, urlparse

import config
from core import finding

_PAYLOADS = [
    '<img src=x onerror="window.__aries_xss=1">',
    '<svg onload="window.__aries_xss=1">',
    '<iframe src="javascript:window.parent.__aries_xss=1"></iframe>',
    '"><img src=x onerror="window.__aries_xss=1">',
]


def dom_xss(url_template):
    host = (urlparse(url_template).hostname or "").lower()
    if host not in config.ALLOWLIST:
        return finding("dom-xss", url_template, "RIFIUTATO", "info",
                       f"host '{host}' fuori ALLOWLIST (lane attiva)", "")
    if "PAYLOAD" not in url_template:
        return finding("dom-xss", url_template, "ERRORE", "info",
                       "l'URL deve contenere il token PAYLOAD dove iniettare", url_template)
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:                       # noqa: BLE001
        return finding("dom-xss", url_template, "ERRORE", "info",
                       "playwright non disponibile", str(e)[:120])

    executed, which = False, None
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            for pl in _PAYLOADS:
                page = browser.new_page()
                fired = {"dialog": False}
                page.on("dialog", lambda d: (fired.__setitem__("dialog", True), d.dismiss()))
                target = url_template.replace("PAYLOAD", quote(pl, safe=""))
                try:
                    page.goto(target, wait_until="load", timeout=15000)
                    page.wait_for_timeout(600)       # lascia girare onerror/onload
                    flag = page.evaluate("() => window.__aries_xss || 0")
                except Exception:                    # noqa: BLE001
                    flag = 0
                page.close()
                if flag or fired["dialog"]:
                    executed, which = True, pl
                    break
        finally:
            browser.close()

    if executed:
        return finding("dom-xss", url_template, "VULNERABILE (DOM-XSS)", "high",
                       "il payload ESEGUE nel browser (DOM) → XSS lato client",
                       f"payload eseguito: {which}")
    return finding("dom-xss", url_template, "non eseguito", "ok",
                   "nessun payload è stato eseguito nel DOM (sanificato o non riflesso)",
                   "provati %d payload" % len(_PAYLOADS))


def run(url_template):
    return [dom_xss(url_template)]
