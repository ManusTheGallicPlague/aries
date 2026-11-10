"""Override LOCALE di config.py — NON tracciato (vedi .gitignore).

Copia questo file in `config_local.py` e mettici i TUOI host: così il repo
pubblico resta privo della tua infrastruttura, ma il tuo ARIES locale sa su cosa
può agire. `config.py` lo importa da solo se presente.

    cp config_local.example.py config_local.py   # poi edita config_local.py

CONFINE: aggiungi SOLO host che possiedi o che sei autorizzato a testare. È il
cuore dell'etica di ARIES — vedi il disclaimer nel README.
"""

# Host aggiuntivi oltre al loopback (uniti all'ALLOWLIST di default di config.py).
ALLOWLIST_EXTRA = {
    # "esempio.tuodominio.tld",
    # "api.tuodominio.tld",
}

# Profili per-bersaglio: endpoint che DEVONO negare l'accesso senza credenziali
# (usati dai gate api/auth del comando `check`).
PROFILES_EXTRA = {
    # "api.tuodominio.tld": {
    #     "api":       ["/api/private"],   # atteso 401/403 senza credenziali
    #     "protected": ["/admin"],         # atteso 302→login oppure 401/403
    # },
}

# (Opzionale) bersaglio del fuzzer di parser `fuzz`: una directory che contiene
# un modulo `formula.py` con `compute(text, ctx)` e l'eccezione `FormulaError`.
# In alternativa, la variabile d'ambiente ARIES_FUZZ_TARGET. Vedi lane_fuzz.py.
# FUZZ_TARGET = "/path/al/tuo/parser/repo"
# FUZZ_CONTEXT = {"a": 1.0, "b": 2.5}
