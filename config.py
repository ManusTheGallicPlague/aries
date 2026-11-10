"""ARIES — configurazione unica. Fonte di verità per CONFINE e bersagli.

Prima c'erano due allowlist sparse in file diversi: una sola fonte evita che
una lane sia più permissiva di un'altra. Ogni lane (anche quelle ATTIVE che
mandano payload) passa da qui.

I TUOI host NON stanno in questo file: così il repo pubblico non espone la tua
infrastruttura. Mettili in `config_local.py` (NON tracciato — vedi .gitignore),
copiandolo da `config_local.example.py`. config.py lo importa da solo se c'è.
"""

# Confine di scope: ARIES agisce SOLO su questi host. Tutto il resto è rifiutato
# da core.probe(), per ogni lane. Il default è SOLO loopback (fixture + bench);
# aggiungi i TUOI host in config_local.py (ALLOWLIST_EXTRA), non qui.
ALLOWLIST = {
    "localhost",
    "127.0.0.1",
}

# Profili per-bersaglio: endpoint che DEVONO negare l'accesso senza credenziali.
# I check generici (header, TLS, esposizioni) valgono ovunque; questi sono
# specifici dell'app perché le rotte cambiano. Vuoto nel repo pubblico: popolalo
# in config_local.py (PROFILES_EXTRA).
PROFILES = {}

TIMEOUT = 15

# --- override LOCALE non tracciato (i TUOI host/profili) ----------------------
# config_local.py sta nel .gitignore: tiene la tua infrastruttura fuori dal repo
# pubblico ma lascia il tuo ARIES locale operativo. Se non c'è, ARIES agisce solo
# sul loopback (fixture/bench).
try:
    import config_local as _local
    ALLOWLIST |= set(getattr(_local, "ALLOWLIST_EXTRA", ()))
    PROFILES.update(getattr(_local, "PROFILES_EXTRA", {}))
except ImportError:
    pass
