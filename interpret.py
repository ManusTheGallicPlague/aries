"""Interprete LLM — Qwen legge i findings GIÀ VERIFICATI dal codice e li
prioritizza/spiega. È l'ultimo layer, e il più delicato: l'LLM NON produce
fatti, lavora solo su ciò che le lane hanno provato. Il suo output è etichettato
"da verificare" — il codice resta la verità.

Gira in locale (Ollama). Se Qwen non c'è, l'interprete degrada in silenzio:
i fatti deterministici restano comunque validi senza di lui.
"""

import json
import urllib.request

OLLAMA = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:14b-instruct-q5_K_M"

SYSTEM = (
    "Sei l'interprete di ARIES, un tool di security testing. Ricevi findings di "
    "sicurezza GIÀ VERIFICATI dal codice (sono fatti provati, non ipotesi). "
    "Compito: in ITALIANO, conciso, prioritizzare e spiegare per un tecnico.\n"
    "REGOLE FERREE:\n"
    "- Usa SOLO i findings forniti. NON inventare vulnerabilità, file, numeri o "
    "dettagli che non sono nei dati. Se un dato non c'è, non lo citi.\n"
    "- Ordina per rischio reale (ALTO prima). I rinvii 'ok' vanno riassunti in "
    "una riga, non elencati.\n"
    "- Per ogni problema: una riga di impatto concreto + il fix, derivati dal "
    "finding.\n"
    "- Se non ci sono problemi (tutto ok), dillo in UNA riga e fermati.\n"
    "- Massimo ~8 righe. Niente preamboli, niente ricopiare la lista grezza."
)


def interpret(target, findings, model=MODEL, timeout=180):
    # compatto i findings: solo i campi utili, evidenza troncata
    compact = [{"check": f["check"], "verdetto": f["verdict"], "severita": f["severity"],
                "dove": f["target"], "prova": (f.get("evidence") or "")[:140]}
               for f in findings]
    body = {
        "model": model, "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content":
                f"Bersaglio: {target}\nFindings (JSON, già verificati):\n"
                + json.dumps(compact, ensure_ascii=False)},
        ],
    }
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return json.load(r).get("message", {}).get("content", "").strip()
    except Exception as e:                       # noqa: BLE001
        return f"(interprete non disponibile — i fatti sopra restano validi: {e})"
