# ARIES

**🇮🇹 Italiano** · [🇬🇧 English](README.md)

Security testing **locale, deterministico e onesto** — attaccante e difensore sulla propria infrastruttura.

> **Principio — ground truth:** i fatti li produce il **codice**, con la prova accanto. L'LLM, quando c'è, al massimo *interpreta* — non decide mai se un controllo passa. ARIES funziona interamente **senza modelli**.

## Confine

ARIES agisce **solo** sugli host in `ALLOWLIST`, controllo imposto dentro `core.probe()` così **nessuna lane lo può aggirare**. Solo la propria infrastruttura e lab autorizzati. Il default è il **solo loopback** (`localhost` / `127.0.0.1`, per il fixture e il `bench`): i tuoi host si aggiungono in un `config_local.py` **non tracciato** — copia `config_local.example.py`, mettici i tuoi domini in `ALLOWLIST_EXTRA`, e `config.py` lo carica da solo (così l'infrastruttura non finisce mai nel repo). Le lane passive sono il default; quelle attive (mandano payload) sono a opt-in esplicito e stampano un avviso.

## Uso autorizzato

ARIES è uno strumento di security testing **offensivo**: alcune lane inviano payload reali. Usalo **solo** su sistemi che possiedi o per cui hai un'autorizzazione **scritta** a testare. Il confine `ALLOWLIST` serve a rendere difficile puntarlo altrove, ma la responsabilità dell'uso resta di chi lo esegue: testare sistemi di terzi senza permesso è illegale in gran parte delle giurisdizioni. Gli autori non si assumono alcuna responsabilità per usi impropri.

## Comandi

```
# Difesa (passiva, sola lettura)
check      igiene web: header (presenza + HSTS/CSP/nosniff/XFO value-aware), cookie (flag + difesa CSRF via SameSite), esposizioni, gate auth/API
secrets    segreti esposti in un repo (orchestra gitleaks, --redact)
sast       vulnerabilità nel codice (orchestra semgrep, rumore domato)
deps       CVE note nelle dipendenze (orchestra trivy)

# Offesa (attiva, opt-in)
discover   endpoint/directory nascosti (orchestra ffuf)
auth       resistenza del login al brute-force (username finto)
attack     SQL injection: error-based + boolean-based + time-based (blind)
xss        reflected XSS lato server
stored-xss stored/persistent XSS: il payload scritto su un endpoint riemerge non-escapato da un altro (due URL)
ssti       Server-Side Template Injection (espressione aritmetica valutata dal template)
dom-xss    DOM-XSS lato client (browser headless, Playwright)
idor       broken access control (header o Bearer token; id in query o nel path)
traversal  path traversal / LFI: un parametro di file esce dalla radice e legge /etc/passwd o \windows\win.ini (anche via troncatura NUL), il wrapper php://filter svela la sorgente di uno script PHP, o il wrapper data:// fa includere ed eseguire uno stream scelto dall'attaccante (RCE)?
nosqli     NoSQL operator injection nel login (bypass auth via $ne/$in; body JSON o bracket-notation form `campo[$op]=`)
jwt        debolezze JWT: alg=none, chiave HS debole (brute offline), exp ignorata
race       race condition / TOCTOU (richieste concorrenti + guardia post-burst anti-FP)
redirect   open redirect (canary esterno, con bypass-allowlist)
crlf       CRLF / HTTP response header injection: un param scrive CR-LF grezzo in un header → split (prova strutturale: l'header-sentinella iniettato riemerge nella risposta)
cors       misconfigurazione CORS: Origin arbitrario riflesso + credenziali (GET + preflight OPTIONS)
ssrf       SSRF: il server segue un URL scelto dal client? (canary locale out-of-band, vale anche per l'SSRF cieca)
tls        igiene TLS/transport: certificato scaduto/non valido, protocollo deprecato (<TLS 1.2) — solo handshake
graphql    GraphQL: introspection esposta, field suggestion ('Did you mean'), query batching senza limite, mutation via GET o form POST (CSRF)
xxe        XXE: un'API che parsa XML risolve le entità esterne? (entità SYSTEM file:///etc/passwd → arbitrary file read; firma del file, non riflessione)
csrf       CSRF: il token anti-CSRF è validato su un endpoint che cambia stato? (prova differenziale)
mass-assign mass assignment: il client può impostare un campo server-controlled (es. role)? (campo-esca come guardia)
nuclei     scanner web a template (orchestra nuclei)

# Discovery
openapi    legge uno spec OpenAPI/Swagger e gira le lane sugli endpoint DICHIARATI
fuzz       fuzzer dei parser: crash e DoS (timeout per hang/ReDoS)

# Motore
scan       compone le lane applicabili + diff di regressione (sentinella); --report → referto Markdown/HTML/SARIF (.sarif → GitHub code scanning)/JUnit (.xml → runner CI); --fail-on <sev> → gate CI assoluto (exit≠0), --fail-on-new <sev> → gate di sola regressione
history    andamento nel tempo di un bersaglio dalla findings-DB (sola lettura): serie degli scan + problemi con la loro età; --report → dashboard Markdown/HTML
bench      auto-validazione: ogni lane attiva con vero positivo + vero negativo
```

Invocazione: `python3 aries.py <comando>`, oppure — dopo `pip install -e .` —
il comando `aries <comando>` da qualunque directory (vedi [Impacchettamento](#impacchettamento-pip-install--e-)).
Ogni comando accetta `--json`.

## Superficie autenticata (sessione: `--cookie` / `--token` / `--header`)

Gran parte della superficie d'attacco reale vive **dietro il login**, dove senza
una sessione si vede solo il muro di autenticazione. I comandi `check`, `xss`,
`scan`, **`attack` (sqli), `ssti`, `nosqli`, `cors`, `ssrf`, `traversal`,
`stored-xss`, `redirect` e `race`** accettano tre flag di **sessione**,
instradati in modo centrale dentro
`core.probe()` (quindi **nessuna lane li può ignorare** e il **confine ALLOWLIST
resta**: la sessione aggiunge credenziali verso lo stesso host autorizzato, non
raggiunge host nuovi):

- `--cookie 'sid=…'` → header `Cookie` (la sessione del browser loggato);
- `--token '<jwt>'` → header `Authorization: Bearer <jwt>` (API a token);
- `--header 'K: V'` → header custom, **ripetibile** (es. `--header 'X-Api-Key: …'`).

```
# reflected XSS su una pagina RISERVATA (senza cookie si vede solo il login wall)
python3 aries.py xss 'http://127.0.0.1:8099/area/cerca?q=X' --param q --cookie 'sess=…'
# igiene degli header valutata sulla pagina AUTENTICATA, non sul login pubblico
python3 aries.py check http://127.0.0.1:8099/dashboard --token "$TOKEN"
python3 aries.py scan http://127.0.0.1:8099/app --active --cookie 'sess=…'
```

Il PoC `curl` riproduce la richiesta autenticata ma **maschera** la credenziale
(Bearer → `$TOKEN`, Cookie → `$COOKIE`): il segreto non entra nel referto.
**Onestà:** senza una sessione valida la lane sulla pagina riservata **tace**
(vede il login wall, non riflette nulla) → ARIES non afferma nulla su una
superficie che non raggiunge. La sessione è instradata — con lo stesso pattern
`probe(session=…)` / `as_curl(session=…)` — in `check`, `xss`, `scan` e in **tutte
le lane attive a target singolo**: **sqli** (`attack`), **ssti**, **nosqli**,
**cors**, **ssrf**, **traversal**, **stored-xss**, **redirect** e **race**.
`stored-xss` la instrada in **entrambe** le probe (scrittura + lettura → una
bacheca dietro il login); `race` non passa da `core.probe` (apre socket urllib
diretti, come `tls`) quindi fonde la sessione negli **header** di ogni richiesta
concorrente, col confine `ALLOWLIST` imposto nella lane. L'inoltro di ciascuna
fino a `core.probe` (o, per `race`, nei suoi header) è verificato dal self-check
dedicato (`SESSION-THREADING`, ora **9 lane**); XSS e SQLi dietro l'autenticazione
hanno il loro benchmark a due facce end-to-end (righe `Auth-XSS`/`Auth-SQLi`), e
lo **stored-XSS dietro il login** ha il suo (riga `Auth-StoredXSS`): senza la
sessione la scrittura è rifiutata e la lettura è il login wall → il canary non
riemerge e la lane **tace** (no FP), con la sessione la bacheca riservata è
raggiunta e la persistenza non-escapata smascherata. Le lane che portano già una
propria identità (`idor`/`jwt` col token, `csrf`/`mass-assign` col `--cookie`) non
usano questi flag generici.

## PoC per costruzione

Ogni finding "VULNERABILE" porta il **comando `curl` esatto che lo riproduce**, generato dalla *stessa* richiesta che la lane manda — non può divergere. I token Bearer sono mascherati con `$TOKEN` (il JWT non finisce nel referto).

## Benchmark

Ogni lane attiva nasce con un benchmark a due facce — becca il **vulnerabile** *e* non segnala il **sicuro**. Un fixture locale (`bench_vuln.py`, solo `127.0.0.1`) lo rigira tutto in un colpo:

```
python3 aries.py bench
echo $?    # 0 se VERDE, 1 se qualcosa regredisce
```

**Exit-code (cancello CI).** `aries bench` esce con **codice 0** solo quando è
**VERDE**: ogni lane non esente a 2/2 (vero positivo + vero negativo) **e** tutti
i self-check non-lane OK. Se una lane regredisce o un self-check fallisce esce con
**codice 1**, così un GitHub Action può **bloccare il commit** che rompe il tool.
La lane `dom-xss` è **esente** dal cancello (richiede Playwright, che in cloud/CI
può mancare): `core.bench_green` la esclude dal punteggio. La decisione è una
funzione **pura** (`core.bench_green`) coperta da un self-check deterministico
(`BENCH-GATE`). Questo repo si auto-controlla con quel cancello a ogni push →
[`.github/workflows/bench.yml`](.github/workflows/bench.yml).

### Banco avversariale — la 3ª faccia

Il bench a due facce prova *vulnerabile* + *sicuro*. Manca il caso **sano ma
ingannevole**: un endpoint che NON è vulnerabile ma ci **somiglia**. Il banco
avversariale è un **cancello globale anti-falso-positivo** (non una lane, non
entra nel punteggio `/N`, come i gate e il referto): punta **ogni lane coperta**
contro la sua trappola e pretende **silenzio** (verdetto non-VULNERABILE) — così
la robustezza di ciò che già esiste è *misurata* contro input cattivi, non solo
contro i fixture a due facce.

Le trappole (in `bench_vuln.py`, solo `127.0.0.1`): **eco verbatim** del payload
(riflette ma non esegue/valuta/include/fetcha), **200-a-tutto** stile SPA (stesso
corpo per ogni input), **eco degli header** di richiesta (Origin/Authorization
nel corpo, mai negli header di risposta), **latenza casuale** sotto-soglia
(jitter di rete). Molte lane hanno già una guardia di questo tipo (la `D` del
CSRF, il canary SSRF, l'esca del mass-assign, il prodotto dell'SSTI, la firma del
traversal, il differenziale eguale-lunghezza del boolean-SQLi): qui la si rende
**sistematica** e benchmarkata per tutte. Il self-check copre **22 lane** (SQLi,
SQLi-time, XSS, Redirect, **CRLF**, CORS, SSTI, NoSQLi, Stored-XSS, CSRF,
Mass-assign, SSRF, Traversal, JWT, GraphQL, **IDOR**, **IDOR-token**,
**IDOR-idecho**, **IDOR-idecho-path**, **Auth**, **Race** e **XXE**). La **CRLF**
è coperta dalla stessa prova strutturale che la definisce: la trappola
`/trap-echo` riflette il payload nel **corpo**, mai in un header →
l'header-sentinella non si materializza → la lane tace (nessun falso positivo da
reflection). La **XXE** è coperta dalla stessa prova strutturale: contro
`/trap-echo` (che riflette il corpo XML — `&xxe;` / il DOCTYPE) la firma
`root:…:0:0:` non si materializza mai → la lane tace (inviamo un *riferimento* a
entità, mai il contenuto del file → l'eco non lo produce).

**IDOR** ha ottenuto la guardia che gli mancava: era l'unica lane *offensiva
differenziale* esclusa dal banco, perché il verdetto era basato sul solo *status*
(owned=200 ∧ other=200) e una trappola 200-a-tutto sarebbe stata letta come
«risorsa altrui accessibile». Ora `lane_idor` confronta anche il **contenuto**:
afferma IDOR solo se, a parità di status 200, il corpo della risorsa altrui
**differisce** dal mio (dati per-utente); se i corpi sono **identici** (SPA
200-a-tutto, risorsa pubblica a corpo costante) tace. Puntata contro `/trap-spa`
(query e token/path) → silenzio.

Una **seconda guardia di contenuto** chiude il caso dell'endpoint **ID-ECHO**:
quello che riflette **solo l'id richiesto** in un guscio costante (es. una SPA che
mette l'id nel corpo, una route aperta a qualunque id). Lì i corpi di `owned` e
`other` **differiscono** — ma per il solo id riflesso, non per dati memorizzati —
quindi la prima guardia (corpi identici) non scatta. La seconda sonda allora un id
**inesistente** (una sentinella deterministica): una **vera risorsa per-id** respinge
l'id ignoto (404/403) → il corpo diverso di `other` sono dati altrui reali → **IDOR
attribuibile**; un endpoint che risponde **200 a qualunque id** (anche inesistente)
**non** è una risorsa per-id memorizzata → la differenza è il solo id riflesso →
la lane **tace**. Puntata contro `/trap-id-echo` (query e path) → silenzio. Una
**normalizzazione** dell'id nei corpi non andrebbe bene (l'id compare spesso *dentro*
i dati per-utente reali, es. `"basket di user 1"` → falsi negativi): la sonda nonce
è il segnale **oggettivo** (store reale vs endpoint aperto), non una soglia di
somiglianza. Limite onesto: un endpoint che restituisce 200 anche per un id
inesistente **e** dati reali per gli altri id verrebbe taciuto — scelta
conservativa verso l'anti-FP, dichiarata.

**Auth** ha ottenuto la trappola dedicata `/trap-auth-lockout`: un login **sano
ma ingannevole** che NON usa il 429 canonico, ma fa lockout per **transizione di
status** (401 ai primi tentativi, poi 403 e ci resta). A uno scanner ingenuo
(che cerca solo 429/423) sembra «nessun throttling» → falso positivo. La lane ha
ora due segnali in più oltre al 429/423: un header **`Retry-After`** (RFC 7231,
status-agnostico) e la **transizione tardiva e persistente** verso uno status
bloccante (`_lockout_transition`, conservativa: un login davvero senza difesa —
stesso status ogni volta — resta VULNERABILE). Puntata contro `/trap-auth-lockout`
→ silenzio (lockout riconosciuto, nessun FP «no rate-limit»).

**Race** ha ottenuto una guardia **post-burst**: il solo conteggio dei successi
concorrenti (ok > 1) non basta, perché una **200-a-tutto** (o un'operazione
idempotente) riesce N× *per costruzione*, non per un TOCTOU. Dopo il burst la
lane manda una richiesta **sequenziale**: un'operazione «una volta sola» ha
consumato la risorsa col burst → la sequenziale è **rifiutata** (non-2xx) → la
race è attribuibile; se invece riesce ancora (2xx) l'endpoint è **ripetibile** →
gli N successi non dimostrano nulla → la lane **tace**. Puntata contro `/trap-spa`
(200-a-tutto, sequenziale post-burst 200) → silenzio. Limite onesto: un'operazione
once-only la cui risorsa non si esaurisce entro il burst (quota > N, o che risponde
2xx idempotente anche dopo il consumo) viene taciuta — scelta conservativa verso
l'anti-FP, dichiarata.

Limiti onesti — lane **non coperte**, e perché:
**DOM-XSS** (richiede Playwright, esente dal bench in cloud);
**TLS** (le trappole sono endpoint HTTP, non server TLS: il verdetto nasce
comunque dal codice di verifica di OpenSSL, non da una stringa riflessa → non
ingannabile per costruzione).

## Ingestione OpenAPI/Swagger

`openapi` legge uno spec (JSON, o YAML se `pyyaml` è presente) ed enumera gli
endpoint **dal contratto** — non li indovina come `discover`. Su ogni operazione
applicabile gira le lane deterministiche: `check` (sulla base), `xss` (reflected
su ogni parametro stringa), `sqli` (sui login con un campo credenziale), `auth`
(resistenza al brute-force dei login), `nosqli` (operator-injection sui login,
opt-in), `ssti` (template injection sui parametri stringa, opt-in), `traversal`
(path traversal / LFI sui parametri file-like, opt-in), `redirect` (open redirect
sui parametri redirect-like in GET, opt-in), `ssrf` (Server-Side Request Forgery
sui parametri URL-like, opt-in), `crlf` (CRLF / response-header injection sui
parametri header-sink in GET, opt-in), `idor`
(lettura di risorse per-id) e `jwt` (debolezze della verifica dei token sulle GET
protette da uno schema bearer — serve il token via flag).
Il dispatch è meccanico: lo spec dichiara nome, posizione e tipo di ogni parametro.
Con `ssrf` e `crlf`, **tutte** le lane a parametro sono dispatchabili dal contratto;
`idor` e `jwt` sono le lane **a token/identità** (lo spec dichiara DOVE serve
l'autenticazione, non il valore della credenziale).

**Composizione dello schema risolta.** Gli spec reali compongono di continuo i
corpi delle richieste: `allOf` (un modello base via `$ref` **più** campi locali),
`oneOf`/`anyOf` (varianti). L'enumerazione dei parametri **risolve** questa
composizione — `allOf` fonde i campi di tutti i membri, `oneOf`/`anyOf` ne prende
l'**unione** (ogni campo che *può* comparire è una superficie iniettabile da
provare), seguendo i `$ref` locali annidati. Senza, un corpo composto esporrebbe
**zero** proprietà (il contenitore `allOf` non ha un `properties` proprio) → il
dispatch salterebbe l'endpoint e la superficie dichiarata dal contratto andrebbe
persa. Il benchmark `OpenAPI-compose` lo prova a due facce: un login il cui corpo
è un `allOf` di un `$ref` (con `username`) e di un membro inline (con `password`)
→ `auth` dispatcha **solo** se riconosce **entrambi** i campi, quindi la riga è
verde ⟺ la composizione è davvero fusa.

- **`auth`** si attiva quando un'operazione POST/PUT/PATCH dichiara nel corpo sia
  un campo **identità** (`username`/`email`/`login`/…) **sia** un campo
  **password** (`password`/`pass`/`pwd`/…): il doppio requisito marca un **login**
  dal contratto, distinguendolo dalla creazione di una risorsa con un campo email
  (su cui il brute-force non avrebbe senso). La lane manda tentativi con uno
  username **finto** (non tocca account reali) e guarda se compare il throttling,
  da tre segnali: **429/423** (throttle esplicito), un header **`Retry-After`**
  (difesa che non cambia lo status), o una **transizione di status** tardiva e
  persistente verso uno status bloccante (es. 401→403 = lockout IP/account /
  step-up, senza il 429 canonico). Nessuno dei tre → VULNERABILE. Non servono
  credenziali reali, quindi è interamente guidabile dallo spec: non si deve più
  *sapere* dov'è il login: lo dice il contratto.
- **`nosqli`** ha lo **stesso trigger** di `auth` (un corpo con campo identità
  **e** campo password = un login dal contratto) e prova la **NoSQL
  operator-injection** sul campo identità (`{"$ne": …}` sempre-vero → bypass se
  valutato). Usa uno username **finto** (non tocca account reali), quindi è
  anch'essa interamente guidabile dal contratto. Il **transport** lo dice il
  content-type dichiarato: un corpo `application/json` → operatore nel body JSON;
  un `application/x-www-form-urlencoded` → bracket-notation `campo[$op]=`. A
  differenza di `auth`, **non** è nel default: va chiesta esplicitamente
  (`--lanes …,nosqli`), per non cambiare l'output di `openapi` senza richiesta. Il
  benchmark `OpenAPI-nosqli` lo prova a due facce (riusa i fixture
  `/nosqli-{vuln,safe}`): il login che **valuta** l'operatore → VULNERABILE, quello
  che lo **coercisce a stringa** → silenzio.
- **`ssti`** ha lo **stesso bersaglio** di `xss` (ogni parametro **stringa**
  riflesso in query/body/form) ma prova la **valutazione lato server** di
  un'espressione di template, non solo la riflessione: inietta `marker{{887*883}}`
  e distingue tre esiti — `marker` + **783221 calcolato** → SSTI confermata; `marker`
  + payload **letterale** → riflesso ma non valutato (semplice reflection, non SSTI,
  la trappola classica dei falsi positivi); marker assente → non riflesso. È
  interamente guidabile dal contratto (nessuna credenziale) ma, come `nosqli`,
  **non** è nel default: va chiesta esplicitamente (`--lanes …,ssti`), per non
  cambiare l'output di `openapi` senza richiesta. Il benchmark `OpenAPI-ssti` lo
  prova a due facce (riusa i fixture `/ssti-{vuln,safe}`): il parametro che passa
  per il motore di template → VULNERABILE, quello **escapato come dato** → silenzio.
- **`traversal`** (Path Traversal / LFI) mira ogni parametro **stringa che porta un
  NOME DI FILE / PATH** (`file`/`page`/`path`/`template`/`download`/…, o un nome che
  contiene `file`/`path`) — **non** ogni parametro stringa: come `idor` sceglie i
  soli id-like nel path, `traversal` sceglie i soli file-param (un `username`/`q`
  non è un file-read). La prova è la **firma oggettiva** (il contenuto di un file di
  sistema noto, es. `root:…:0:0:`), non la riflessione → un parametro riflesso crudo
  non la produce, quindi lo spray sui file-param non introduce falsi positivi. È
  interamente guidabile dal contratto (nessuna credenziale) ma, come `nosqli`/`ssti`,
  **non** è nel default: va chiesta esplicitamente (`--lanes …,traversal`), per non
  cambiare l'output di `openapi` senza richiesta. Il benchmark `OpenAPI-trav` lo
  prova a due facce (riusa i fixture `/download-{vuln,safe}?file=`): il download che
  fa join ingenuo del nome → `../` esce dalla radice → VULNERABILE, quello che riduce
  a **basename** → confinato → silenzio.
- **`idor`** si attiva su ogni operazione **GET** con un parametro **id-like nel
  PATH** (`/basket/{id}`, `/users/{userId}`, `…/{order_id}`): una lettura di
  risorsa per-identificatore. Quel placeholder diventa il punto in cui `idor`
  sostituisce la risorsa **tua** e quella **altrui**; gli altri placeholder sono
  concretizzati a un valore campione. A differenza di `auth`, `idor` **non** è nel
  default e richiede un'**identità** (`--token`, oppure `--id-header` +
  `--identity`): lo spec la dichiara come requisito (`securitySchemes`) ma non ne
  porta il *valore*. Se chiedi `--lanes …,idor` senza passarla, la lane non viene
  eseguita e `openapi` lo dichiara (finding `idor:spec`, info).
- **`redirect`** (open redirect) mira ogni operazione **GET** con un parametro
  **stringa di QUERY redirect-like** (`to`/`url`/`next`/`redirect`/`return`/…, o
  un nome che contiene `redirect`/`return`) — **non** ogni parametro stringa: come
  `traversal` sceglie i soli file-param e `idor` i soli id-like nel path,
  `redirect` sceglie i soli parametri redirect-like (un `q`/`username` non
  reindirizza). La prova è la **firma oggettiva** (un `3xx` con `Location` verso il
  **canary esterno** `example.com`, mai contattato — `core.probe` non segue i
  redirect), non la riflessione → un parametro riflesso crudo non la produce,
  quindi lo spray sui redirect-param non introduce falsi positivi. È interamente
  guidabile dal contratto (nessuna credenziale) ma, come `nosqli`/`ssti`/`traversal`,
  **non** è nel default: va chiesta esplicitamente (`--lanes …,redirect`), per non
  cambiare l'output di `openapi` senza richiesta.
- **`ssrf`** (Server-Side Request Forgery) mira ogni parametro **stringa che porta
  una URL** che il server andrà a **richiedere** (`url`/`uri`/`webhook`/`callback`/
  `src`/`image`/…, o un nome che contiene `url`/`webhook`/`callback`) — **non** ogni
  parametro stringa: come `redirect` sceglie i soli redirect-like, `traversal` i soli
  file-param e `idor` i soli id-like, `ssrf` sceglie i soli parametri URL-like (un
  `q`/`username`/`page` non innesca un fetch server-side; `uri` è un nome **esatto**,
  non una sottostringa, per non abboccare a `security`/`maturity`). La prova è
  **oggettiva e out-of-band** (il **canary locale** colpito col nonce, non la
  riflessione), quindi un parametro riflesso crudo non la produce → lo spray sui soli
  URL-param non introduce falsi positivi. Il **transport** lo dice la posizione
  dichiarata: un parametro di **query** → fetcher via GET; un campo di **body/form**
  → webhook via POST. È interamente guidabile dal contratto (nessuna credenziale) ma,
  come `nosqli`/`ssti`/`traversal`/`redirect`, **non** è nel default: va chiesta
  esplicitamente (`--lanes …,ssrf`), per non cambiare l'output di `openapi` senza
  richiesta.
- **`crlf`** (CRLF / HTTP Response Header Injection) mira ogni operazione **GET**
  con un parametro **stringa di query HEADER-SINK** — il cui valore può finire in
  un **header di risposta**: il sink canonico è il `Location` di un redirect, così
  l'insieme è l'**unione** dei nomi redirect-like **e** url-like (`to`/`url`/`next`/
  `redirect`/`webhook`/…) — **non** ogni parametro stringa: come `redirect` sceglie
  i soli redirect-like e `ssrf` i soli url-like, `crlf` mira i soli header-sink (un
  `q`/`username` non finisce in un header). La prova è **oggettiva e strutturale**
  (l'header-sentinella iniettato **riemerge come header di risposta** → il CR-LF è
  stato scritto grezzo e ha spezzato l'header), non la riflessione nel corpo →
  un parametro riflesso crudo non la produce, quindi lo spray sui soli header-sink
  non introduce falsi positivi. È interamente guidabile dal contratto (nessuna
  credenziale) ma, come `nosqli`/`ssti`/`traversal`/`redirect`/`ssrf`, **non** è nel
  default: va chiesta esplicitamente (`--lanes …,crlf`). Con `ssrf` e `crlf`,
  **tutte** le lane a parametro sono dispatchabili dal contratto.
- **`jwt`** (debolezze della verifica dei token) si attiva su ogni operazione
  **GET** che lo spec dichiara **protetta da uno schema bearer**
  (`securitySchemes` con `type: http, scheme: bearer`): è lì che un
  `Authorization: Bearer <token>` è accettato → è lì che ha senso provare
  `alg=none`, la **chiave HS debole** (brute offline) e la **`exp` ignorata**. A
  differenza di `xss`/`ssti` (ogni parametro), `jwt` mira i soli endpoint che il
  **contratto** dichiara protetti — come `idor` mira i soli id-like nel path.
  Come `idor`, lo spec dice **dove** il token è accettato ma **non** ne porta il
  *valore*: il token legittimo arriva via `--token`; se chiedi `--lanes …,jwt`
  senza passarlo, la lane non viene eseguita e `openapi` lo dichiara (finding
  `jwt:spec`, info). Solo **GET** (lettura, nessun effetto collaterale, come
  `idor`). Il verdetto è **oggettivo** (un token forgiato accettato con HTTP 200,
  o la firma ricostruita offline), con la guardia anti-FP della lane (una firma
  **rotta** rifiutata → il bypass è attribuibile). `jwt` e `idor` sono le due lane
  **a token/identità** del dispatch.

```
python3 aries.py openapi api-spec.json
python3 aries.py openapi api-spec.yaml --base http://127.0.0.1:8099 --lanes xss,sqli,auth --json
# NoSQLi dal contratto: opt-in sui login dichiarati (username + password nel corpo)
python3 aries.py openapi api-spec.json --lanes nosqli
# SSTI dal contratto: opt-in sui parametri stringa riflessi (valutazione template lato server)
python3 aries.py openapi api-spec.json --lanes ssti
# Traversal dal contratto: opt-in sui parametri file-like (path traversal / LFI)
python3 aries.py openapi api-spec.json --lanes traversal
# Open redirect dal contratto: opt-in sui parametri redirect-like in GET
python3 aries.py openapi api-spec.json --lanes redirect
# SSRF dal contratto: opt-in sui parametri URL-like (fetcher/webhook server-side)
python3 aries.py openapi api-spec.json --lanes ssrf
# CRLF dal contratto: opt-in sui parametri header-sink in GET (response-header injection)
python3 aries.py openapi api-spec.json --lanes crlf
# IDOR dal contratto: identità via flag (lo spec dice DOVE, non CHI sei)
python3 aries.py openapi api-spec.json --lanes idor --token "$TOKEN" --owned 1 --other 2
# JWT dal contratto: token via flag sulle GET protette da schema bearer
python3 aries.py openapi api-spec.json --lanes jwt --token "$TOKEN"
```

Limiti onesti: `idor` mira le sole GET con id-like nel path (le letture
per-identificatore, dove il verdetto è oggettivo sullo status owned=200 ∧
other=200 **con corpi diversi** — vedi la guardia di contenuto nel banco
avversariale); le scritture per-id (PUT/DELETE/`{id}`) hanno effetti collaterali e
restano fuori dall'auto-dispatch. `traversal` mira i soli parametri **stringa
file-like** (nome noto, o che contiene `file`/`path`): un parametro che porta un
file-name non dichiarato con un nome riconoscibile non viene dispatchato (scelta
onesta — il traversal su `username`/`q` sarebbe rumore), ma può sempre essere
provato con la lane diretta `traversal`. `redirect` mira le sole **GET** con un
parametro **stringa di query redirect-like** (nome noto, o che contiene
`redirect`/`return`): un parametro di redirect con nome non riconoscibile non
viene dispatchato (scelta onesta — come per `traversal`), ma resta provabile con
la lane diretta `redirect`. `ssrf` mira i soli parametri **stringa URL-like** (nome
noto, o che contiene `url`/`webhook`/`callback`): un parametro-URL con nome non
riconoscibile non viene dispatchato (scelta onesta — come per `traversal`/`redirect`;
`uri` è un nome esatto, non una sottostringa, per non abboccare a `security`), ma
resta provabile con la lane diretta `ssrf`; il suo canary resta un listener locale
`127.0.0.1` (dentro l'`ALLOWLIST`). `crlf` mira le sole **GET** con un parametro
**stringa di query header-sink** (l'unione dei nomi redirect-like e url-like — il
cui valore può finire in un header di risposta, il sink canonico è `Location`): un
parametro header-sink con nome non riconoscibile non viene dispatchato (scelta
onesta — come per `traversal`/`redirect`/`ssrf`), ma resta provabile con la lane
diretta `crlf`; la prova resta strutturale (l'header-sentinella riemerge come
header di risposta). `jwt` mira le sole **GET** che lo spec dichiara protette da
uno schema **bearer** (`securitySchemes` con `type: http, scheme: bearer`,
richiesto via `security` globale o d'operazione): un endpoint protetto da uno
schema non-bearer (apiKey/oauth2/basic) o non dichiarato protetto non viene
dispatchato (scelta onesta — il JWT si prova solo dove il contratto dice che un
Bearer è accettato), ma resta provabile con la lane diretta `jwt`; serve il
**token** via `--token` (lo spec dice DOVE, non il valore), e il PoC `curl`
maschera il Bearer con `$TOKEN` (il JWT vittima non entra nel referto).
La risoluzione `$ref` è solo **locale** (`#/...`); la **composizione** dello
schema (`allOf`/`oneOf`/`anyOf`, anche con `$ref` annidati) è risolta
nell'enumerazione dei parametri. Spec remoti/federati fuori scope.

## Debolezze JWT

`jwt` parte da un token **valido** (quello dell'utente legittimo) e dall'endpoint
che lo accetta, poi forgia richieste concrete — non indovina. Tre controlli
oggettivi, puro Python (`hmac`/`base64`):

- **alg=none** — token con header `{"alg":"none"}` e firma vuota (varianti
  `none/None/NONE/nOnE`). Se il server lo accetta → nessuna verifica di firma.
- **chiave HS\* debole** — rifà l'HMAC su `header.payload` per ogni voce di una
  wordlist piccola (`wordlists/jwt-secrets.txt`) e la confronta con la firma
  reale. Match = chiave indovinabile → token forgiabili. **100% offline.**
- **`exp` ignorata** — se la chiave è nota (crackata) o `alg=none` passa, forgia
  un token per il resto valido ma **scaduto**: se il server lo accetta, non
  controlla la scadenza.

```
python3 aries.py jwt http://127.0.0.1:8099/api "<JWT valido>"
python3 aries.py jwt http://host/api "$TOKEN" --wordlist mie-chiavi.txt --json
```

**Guardia anti falso positivo (firma di controllo).** Prima dei controlli
*online* (alg=none, exp, conferma della chiave debole) la lane manda un token con
la stessa testa/payload ma **firma rotta** (byte arbitrari, nessun segreto la
produce). Se il server lo **rifiuta** (≠ 200), verifica davvero le firme → un
eventuale 200 su `alg=none` è **attribuibile** a un bypass. Se invece lo
**accetta** come il valido, l'endpoint non verifica le firme (o non è protetto):
l'accettazione di un token forgiato non prova nulla → la lane **tace** su quei
controlli (stessa logica della guardia `D` del CSRF / del canary SSRF).

Onestà sui token: il JWT della **vittima** non finisce nel referto; i PoC `curl`
mascherano il Bearer con `$TOKEN` e l'evidenza descrive la ricetta della
forgiatura (header/payload/firma), non la credenziale.

## NoSQL operator injection

`nosqli` chiede: il login costruisce una query NoSQL concatenando l'input, così
che un **operatore** (stile MongoDB) nel body JSON venga *valutato* invece di
essere trattato come dato? La prova è **differenziale e oggettiva**, come il
boolean-based SQLi — tre richieste al posto del valore di un campo:

- **BASELINE** — credenziali letterali sbagliate → login negato (atteso).
- **TRUE-op** — `{"$ne": "<nonce>"}` ("diverso da un valore inesistente", quindi
  sempre vero): se il server valuta l'operatore, la condizione sul campo è
  sempre soddisfatta → **bypass dell'autenticazione**.
- **FALSE-op** — `{"$in": []}` (insieme vuoto, sempre falso) → resta negato.

Se il TRUE-op differisce dalla baseline negata **e** il FALSE-op resta uguale
alla baseline → l'operatore è stato interpretato come query → **NoSQL
injection** (ALTO). Il controllo anche sul FALSE-op chiude il falso positivo del
server che va in errore su *qualsiasi* oggetto (lì il FALSE divergerebbe dalla
baseline e la lane tace).

**Due transport (`--as json|form`).** Il vettore NoSQLi vive in due posti e la
lane li copre entrambi con lo **stesso** metodo differenziale:

- **`--as json`** (default) — l'operatore sta nel **body JSON**
  (`{"username": {"$ne": …}}`): il vettore più comune per le API.
- **`--as form`** — **bracket-notation** form-urlencoded (`username[$ne]=…`): è
  così che gli stack **Express** (`qs`/`body-parser` con `extended: true`) e
  **PHP** ricostruiscono un dict annidato da una chiave con parentesi, portando
  l'operatore nella query anche **fuori dal body JSON** (query-string/form). In
  questo transport l'operatore sempre-falso della guardia è `$eq:<nonce>` (un
  insieme vuoto `$in: []` non è esprimibile in bracket-notation), ugualmente un
  dict: un server che va in errore su qualsiasi oggetto fa divergere il FALSE-op
  dalla baseline → la lane **tace** (stessa guardia anti-FP del JSON).

```
python3 aries.py nosqli http://127.0.0.1:8099/api/login
python3 aries.py nosqli http://host/login --user-field email --pass-field pass --json
# bracket-notation (Express/PHP): l'operatore viaggia in `campo[$op]=` nel form
python3 aries.py nosqli http://host/login --as form
```

Puro Python, nessuna dipendenza. ATTIVO: manda payload, solo host in
`ALLOWLIST`. Il PoC `curl` è costruito dalla stessa richiesta TRUE-op che
dimostra il bypass (JSON o `campo[$ne]=` urlencoded). Il benchmark è a **due
facce per transport**: `NoSQLi` (body JSON) **e** `NoSQLi-bracket` (form) — il
vuln di ciascuno ricostruisce/valuta l'operatore nel proprio transport, il safe
lo tratta come stringa. Limite onesto: copre l'operator-injection su endpoint
login-like via `$ne`/`$in`/`$eq`; altre varianti di parsing (array annidati più
profondi, operatori diversi) restano fuori dal modello minimale.

## Stored / persistent XSS

`stored-xss` copre il XSS **persistente**, una superficie diversa dal reflected:
l'input entra da un endpoint di **scrittura** (`POST /commento`) e riemerge —
magari più tardi, verso un'altra vittima — da un endpoint di **lettura**
(`GET /commenti`). La lane `xss` puntata contro l'endpoint di lettura **non lo
vede**: il payload non sta in un suo parametro ma nello **stato persistito** dal
server. La prova è oggettiva come il reflected, ma su **due richieste**:

1. **scrittura** — invio un canary unico coi caratteri pericolosi (`<ar>`);
2. **lettura** — faccio una richiesta al secondo endpoint e guardo il corpo.

- **ALTO — VULNERABILE (stored)**: il canary riemerge **crudo** (`<ar>`) nella
  lettura → persistito e reso non-escapato → stored XSS.
- **ok — persistito ma escapato**: il canary c'è ma `&lt;ar&gt;` (output
  encoding corretto in lettura).
- **ok — non persistito/non reso**: il canary non riemerge dall'endpoint di
  lettura.

Il token casuale nel canary garantisce che il match sia proprio ciò che abbiamo
appena scritto, non un residuo vecchio della bacheca.

```
python3 aries.py stored-xss http://127.0.0.1:8099/comment http://127.0.0.1:8099/comments
python3 aries.py stored-xss http://host/post http://host/feed --param body --as form --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda payload, solo host in
`ALLOWLIST`. Il PoC `curl` è costruito dalla stessa richiesta di **scrittura**
che inietta il canary (la lettura è una GET semplice, descritta nell'evidenza).
I flag di **sessione** (`--cookie`/`--token`/`--header`) sono instradati in
**entrambe** le probe → una bacheca **dietro il login** (scrittura e lettura
riservate) è raggiungibile; il benchmark `Auth-StoredXSS` lo prova a due facce.
Limite onesto: come il reflected, la prova è la presenza del canary **crudo**
nel corpo reso (assume che la lettura sia HTML, non un dato JSON); i due
endpoint vanno indicati (è la natura stessa del vettore stored, non
un'assunzione della lane).

## CSRF — enforcement del token anti-CSRF

`csrf` chiede: una richiesta che **cambia stato** viene eseguita in base al
**solo cookie di sessione** (l'autorità ambientale che il browser allega da
solo, anche su richieste cross-site), o il server pretende un token anti-CSRF
imprevedibile e lo **valida**? La prova è **differenziale e oggettiva** come il
boolean-based SQLi — tre richieste alla stessa operazione, una variabile cambiata
per volta:

- **A — LEGITTIMA**: cookie di sessione + token CSRF corretto → esito di riferimento.
- **C — TOKEN FORGIATO**: cookie di sessione + token CSRF **sbagliato**. Se l'esito
  è **identico** ad A, il token non è validato: il solo cookie decide → la
  richiesta è **forgeable cross-site**.
- **D — SENZA COOKIE**: token corretto ma **nessuna** sessione. Guardia: deve
  cambiare esito (l'endpoint è davvero autenticato via cookie).

CSRF dimostrata ⟺ **C = A** (token errato accettato come il giusto) **e** **D ≠ A**
(il cookie invece conta). La guardia D chiude il falso positivo dell'endpoint che
risponde **uguale a tutto** (aperto/morto): lì anche togliere il cookie non
cambierebbe nulla (D = A) e la lane **tace** — non c'è una sessione la cui
autorità venga abusata cross-site.

```
python3 aries.py csrf http://127.0.0.1:8099/account/email --cookie "session=..." --token "<token-csrf-valido>"
python3 aries.py csrf http://host/transfer --cookie "sid=..." --token "..." --as json --data 'amount=100&to=acme' --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda richieste che **cambiano stato**,
solo host in `ALLOWLIST`. Il PoC `curl` è costruito dalla stessa richiesta C
(cookie + token errato) con il **Cookie mascherato** (`$COOKIE`): il browser
della vittima allega il suo cookie da solo, ed è questa la forgiatura. Limite
onesto: prova la **mancata validazione del token** su un endpoint
cookie-autenticato (il cuore del CSRF); non modella i preflight. La difesa
**passiva** via attributo **SameSite** sui cookie è complementare e la copre il
comando `check` (vedi sotto).

### Difesa CSRF passiva via SameSite (in `check`)

Complementare alla lane attiva `csrf`, il comando passivo `check` valuta se il
cookie di sessione porta `SameSite=Lax/Strict` — l'attributo che impedisce al
browser di allegarlo sulle richieste cross-site, quindi un **argine CSRF** a
costo zero. Il controllo è **value-aware**, non guarda solo la presenza della
stringa: `SameSite=None` (o attributo **assente**) è segnalato come
`cookie-samesite: DIFESA CSRF ASSENTE` (MEDIO), perché un `None` *presente* non
protegge da nulla — è il falso negativo che il vecchio check sulla sola presenza
non vedeva. Resta distinto da `cookie-flags` (che verifica che Secure + HttpOnly
+ SameSite ci *siano*): i due findings rispondono a domande diverse (gli
attributi sono impostati? / il valore di SameSite difende davvero dal CSRF?).

### Difesa HSTS value-aware (in `check`)

Stessa classe di falso negativo sul **valore** dell'header, applicata all'HSTS:
`check` non si limita a vedere se `Strict-Transport-Security` è *presente*, ma
valuta se il suo `max-age` difende davvero. Un `max-age=0` **disattiva** l'HSTS
— ordina al browser di *dimenticare* la policy (è l'idioma canonico per
spegnerlo) → l'header è presente ma **non** protegge dall'SSL-strip; un `max-age`
assente o non numerico è ugualmente inerte. Il controllo di presenza
`header:strict-transport-security` lo direbbe «presente/ok» (falso senso di
sicurezza): il finding **distinto** `hsts-maxage: HSTS DISATTIVATO` (MEDIO)
smaschera il valore inerte, esattamente come `cookie-samesite` rispetto a
`cookie-flags`. È emesso **solo quando l'header esiste** (l'assenza è già
segnalata come `header:strict-transport-security MANCANTE` → non la si raddoppia).
Funzione **pura** `lane_check.hsts_active(valore)` coperta dal self-check `HSTS`
nel `bench` (fixture a due facce `/hsts-{weak,strong}`: entrambi impostano
l'header, `weak` con `max-age=0`, `strong` con `max-age` valido → la riga è verde
⟺ il value-aware distingue davvero il presente-ma-inerte dal presente-e-attivo).

### Difesa CSP value-aware (in `check`)

Stessa classe di falso negativo sul **valore**, applicata alla
`Content-Security-Policy`: una CSP **presente** può essere **inerte contro
l'XSS**. Il finding **distinto** `csp-xss: CSP INERTE contro XSS` (MEDIO)
smaschera due valori **oggettivamente** inerti (fatti del linguaggio CSP, non
soglie di policy):

- la direttiva effettiva (`script-src`, o `default-src` come fallback) contiene
  **`'unsafe-inline'` senza alcun nonce/hash** → gli script inline iniettati
  (`<script>…`, handler `on*`) **eseguono** a dispetto della CSP;
- **né `script-src` né `default-src`** presenti → la CSP non limita affatto gli
  script.

Con un **nonce o un hash** presente i browser CSP2+ **ignorano** `'unsafe-inline'`
(è un fallback di retro-compatibilità, non un buco) → in quel caso la CSP **non**
è dichiarata inerte, per non introdurre falsi positivi. `'unsafe-eval'` da solo
**non** ribalta il verdetto: la CSP blocca comunque uno `<script>` iniettato
(indebolisce i soli sink basati su `eval`) → **onestà**, ci si ferma ai valori
inerti contro l'XSS inline. Più policy nello stesso header (separate da virgole)
sono imposte in **intersezione**: la CSP è inerte solo se **nessuna** policy
blocca l'inline. Il controllo di presenza `header:content-security-policy` lo
direbbe «presente/ok» (falso senso di sicurezza): il finding distinto smaschera
il valore inerte, come `hsts-maxage` e `cookie-samesite` rispetto ai loro
gemelli; è emesso **solo quando l'header esiste** (l'assenza è già
`header:content-security-policy MANCANTE`). Funzione **pura**
`lane_check.csp_xss_active(valore)` coperta dal self-check `CSP` nel `bench`
(fixture a due facce `/csp-{weak,strong}`: entrambi impostano l'header, `weak`
con `script-src 'unsafe-inline'`, `strong` con un **nonce** → la riga è verde ⟺
il value-aware distingue il presente-ma-inerte dal presente-e-efficace).

### Difesa MIME-sniffing value-aware — X-Content-Type-Options (in `check`)

Stessa classe di falso negativo sul **valore**, applicata a
`X-Content-Type-Options`: l'**unico** valore che disabilita il MIME-sniffing è
`nosniff` — un **fatto del linguaggio**, non una soglia di policy. I browser
seguono l'algoritmo *determine nosniff* di WHATWG Fetch: prendono il **primo
token** della lista (separata da virgole), lo confrontano **case-insensitive**
con `nosniff` e **ignorano** ogni altro valore. Un header **presente** con un
valore diverso (`none`, `sniff`, vuoto, o `nosniff` **non** in prima posizione)
è quindi presente ma **inerte** — il browser continua a **indovinare** il tipo
di contenuto (vettore di XSS da upload / drive-by). Il controllo di presenza
`header:x-content-type-options` lo direbbe «presente/ok» (falso senso di
sicurezza): il finding **distinto** `xcto-nosniff: NOSNIFF INERTE` (BASSO)
smaschera il valore inerte, come `hsts-maxage`/`csp-xss`/`cookie-samesite`
rispetto ai loro gemelli; è emesso **solo quando l'header esiste** (l'assenza è
già `header:x-content-type-options MANCANTE`). Funzione **pura**
`lane_check.xcto_active(valore)` coperta dal self-check `XCTO` nel `bench`
(fixture a due facce `/xcto-{weak,strong}`: entrambi impostano l'header, `weak`
con `none`, `strong` con `nosniff` → la riga è verde ⟺ il value-aware distingue
il presente-ma-inerte dal presente-e-efficace).

### Difesa anti-clickjacking value-aware — X-Frame-Options (in `check`)

Stessa classe di falso negativo sul **valore**, applicata a `X-Frame-Options`:
gli **unici** valori che difendono dal clickjacking sono `DENY` e `SAMEORIGIN`
— un **fatto del linguaggio**, non una soglia di policy. Il deprecato
`ALLOW-FROM <uri>` è **ignorato** dai browser moderni (Chrome, Safari, Firefox
70+), e ogni altro valore (vuoto, `ALLOWALL`, garbage) non limita il framing: un
header **presente** con uno di questi valori è quindi presente ma **inerte** — la
pagina resta inquadrabile in un iframe ostile (vettore di clickjacking /
UI-redressing). Il controllo di presenza `header:x-frame-options` lo direbbe
«presente/ok» (falso senso di sicurezza): il finding **distinto**
`xfo-clickjack: X-FRAME-OPTIONS INERTE` (BASSO) smaschera il valore inerte, come
`xcto-nosniff`/`hsts-maxage`/`csp-xss`/`cookie-samesite` rispetto ai loro
gemelli; è emesso **solo quando l'header esiste** (l'assenza è già
`header:x-frame-options MANCANTE`). Funzione **pura** `lane_check.xfo_active(valore)`
coperta dal self-check `XFO` nel `bench` (fixture a due facce `/xfo-{weak,strong}`:
entrambi impostano l'header, `weak` con `ALLOW-FROM …`, `strong` con `DENY` → la
riga è verde ⟺ il value-aware distingue il presente-ma-inerte dal
presente-e-efficace). **Onestà:** X-Frame-Options è una delle due difese
anti-clickjacking — la CSP `frame-ancestors` è la gemella (defense-in-depth) e
può coprire il caso anche con un XFO inerte → il finding afferma che il **valore
dell'header XFO** è inerte, non che la pagina sia clickjackable; ci si ferma al
valore oggettivamente inerte (≠ `DENY`/`SAMEORIGIN`), non a una soglia di policy.

## Mass assignment (autobinding / object injection)

`mass-assign` chiede: un endpoint che aggiorna/crea una risorsa lega al modello
**tutti** i campi del corpo, lasciando al client impostare un campo che dovrebbe
essere **server-controlled** (es. `role`, `isAdmin`, `verified`, `balance`)? La
prova è **differenziale e oggettiva** su due richieste, come lo stored-XSS:

1. **scrittura** — invio i campi legittimi **+** il campo privilegiato (`--field`,
   default `role`) con un **valore-nonce unico** **+** un **campo-esca** dal nome
   inventato, che nessun modello reale possiede, con un altro nonce;
2. **lettura** — rileggo lo stato (un endpoint `GET`, o il corpo della risposta di
   scrittura) e cerco i due nonce.

- **ALTO — VULNERABILE (mass assignment)**: il nonce del **campo privilegiato**
  riemerge **e** quello dell'**esca no** → il server ha fatto binding *selettivo*
  a una colonna reale del modello (`role`) scartando l'esca inesistente: il client
  controlla un campo che non dovrebbe.
- **ok — eco indiscriminato**: riemergono **entrambi** i nonce → l'endpoint fa
  l'**eco** verbatim del corpo (o è schema-less), non un binding a un modello: il
  mass assignment non è dimostrabile → la lane **tace** (guardia anti falso
  positivo, come la `D` del CSRF).
- **ok — campo scartato**: il nonce privilegiato **non** riemerge → whitelist
  server-side.

Il **campo-esca** è la guardia che separa il binding selettivo dall'eco del
corpo; il nonce casuale garantisce che il match sia proprio ciò che abbiamo
appena scritto.

```
python3 aries.py mass-assign http://127.0.0.1:8099/profile --field role
python3 aries.py mass-assign http://host/user/update --read-url http://host/user/me \
        --field isAdmin --value true --data 'name=x' --cookie "sid=..." --as json --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda richieste di scrittura, solo host
in `ALLOWLIST`. Il PoC `curl` è costruito dalla stessa richiesta di scrittura che
inietta il campo privilegiato, col Cookie mascherato `$COOKIE`. Limite onesto:
inietta un valore-**nonce**; se il server **valida** il valore del campo (enum,
es. `role ∈ {user,admin}`) il nonce viene scartato → falso negativo → si mira un
valore reale con `--value admin`. La prova è la presenza del nonce privilegiato
nel corpo di lettura (assume che quel corpo rifletta lo stato persistito).

## Misconfigurazione CORS

`cors` chiede: il server si fida di **chi** manda la richiesta? Invia un header
`Origin` **arbitrario** (mai un host reale: sta solo nell'header, il bersaglio
resta in `ALLOWLIST`) e legge la coppia che decide la condivisione cross-origin —
`Access-Control-Allow-Origin` (ACAO) e `Access-Control-Allow-Credentials` (ACAC).
Puro Python, nessuna dipendenza. Ogni origine è provata in **due fasi**: la
richiesta **semplice** (GET con `Origin`) e il **preflight `OPTIONS`** con
metodo/header non-simple (`Access-Control-Request-Method`/`-Headers`). La seconda
fase becca i server che riflettono l'origine **solo** nel preflight (molti
middleware CORS lo gestiscono separatamente) o solo per richieste non-simple
(PUT/DELETE, header custom come `Authorization`): senza il preflight passerebbero
per sicuri. Classificazione oggettiva, tenuto il peggio tra le fasi e una
batteria di origini (arbitraria · `null` · sottodominio sotto dominio
attaccante, per i validatori ingenui `startswith`):

- **CRIT** — origine arbitraria **riflessa** in ACAO **e** ACAC `true`: un sito
  malevolo, con la sessione della vittima, legge le risposte autenticate
  cross-origin (furto dati/sessione).
- **MEDIO** — origine arbitraria riflessa ma **senza** credenziali (lettura delle
  sole risposte non autenticate).
- **BASSO** — `ACAO: *` con ACAC `true`: i browser **rifiutano** questa
  combinazione con fetch credenziato → inerte, ma configurazione da correggere.
- **INFO/ok** — `ACAO: *` senza credenziali (API pubblica, atteso) oppure nessuna
  origine arbitraria riflessa (allowlist attiva / CORS assente).

```
python3 aries.py cors http://127.0.0.1:8099/api/profilo
python3 aries.py cors http://host/api --json
```

## CRLF / HTTP Response Header Injection

`crlf` chiede: un parametro il cui valore finisce in un **header di risposta** (il
caso canonico è `Location` di un redirect, ma anche i `Set-Cookie` costruiti
dall'input) viene scritto **grezzo**, così che una sequenza **CR-LF** nel valore
**spezzi** l'header e ne inietti uno nuovo scelto dall'attaccante? È il cuore
dell'**HTTP response splitting** (CWE-113): da lì cache-poisoning, `Set-Cookie`
forgiati (session fixation), o un corpo iniettato (XSS riflesso via split).

La prova è **oggettiva e strutturale**, non la riflessione. Iniettiamo nel
parametro un valore `<prefisso>CRLF X-Aries-Crlf: <nonce>` e poi guardiamo gli
**header della RISPOSTA**:

- **ALTO — VULNERABILE (CRLF injection)**: l'header `X-Aries-Crlf` col nostro
  nonce **riemerge come header di risposta** → il server ha scritto il CR-LF
  grezzo in un header e l'ha **spezzato**, materializzando l'header iniettato.
- **ok — nessuna injection**: il CR-LF iniettato **non** materializza un header
  (valore neutralizzato o non scritto in un header).

Un endpoint che si limita a **riflettere** il valore nel **corpo** non produce
mai un header di risposta → la lane **tace**: la **struttura** della risposta *è*
la guardia anti falso positivo (come il canary dell'SSRF, il prodotto calcolato
dell'SSTI, la firma del traversal). Il nonce è casuale per run, così il match è
attribuibile proprio alla nostra iniezione. Proviamo **due separatori** —
**CRLF** (`\r\n`, il classico) e **LF** solo (`\n`, alcuni parser spezzano anche
senza il CR) — così un filtro che toglie l'uno ma non l'altro resta smascherato.

```
python3 aries.py crlf 'http://127.0.0.1:8099/redirect?to=X' --param to
python3 aries.py crlf http://host/redirect --param url --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda una richiesta al bersaglio, solo
host in `ALLOWLIST` (il valore iniettato resta nella richiesta verso lo stesso
host autorizzato; nessun host esterno è contattato). Il PoC `curl` è costruito
dalla stessa richiesta d'iniezione; i flag di **sessione**
(`--cookie`/`--token`/`--header`) sono instradati via `core.probe` (PoC
mascherato `$TOKEN`/`$COOKIE`) → raggiunge un sink dietro il login. Limite
onesto: prova l'iniezione di un **header** via CR-LF (il cuore del response
splitting); l'escalation concreta (cache-poisoning, XSS via corpo iniettato)
dipende dall'infrastruttura a valle e non viene assunta. Il benchmark è a due
facce (`CRLF`): il vuln scrive il valore grezzo in `Location`, il safe neutralizza
CR/LF → la lane tace.

## XXE — XML External Entity injection

`xxe` chiede: un endpoint che **parsa un documento XML** inviato dal client lo fa
con un parser che **risolve le entità esterne**? In quel caso un attaccante
dichiara nel DOCTYPE un'entità `SYSTEM "file:///etc/passwd"` e, referenziandola in
un nodo, fa **leggere al server un file arbitrario** (arbitrary file read → furto
di configurazioni/segreti; CWE-611, storicamente OWASP A4:2017-XXE, confluita in
**A05:2021** Security Misconfiguration). È una classe di **parsing**, distinta da
tutte le altre lane: `traversal` legge file via un parametro *nome-di-file*, qui
il vettore è l'**entità** del documento XML.

La prova è **oggettiva via firma di un file di sistema noto**, nello stesso
spirito del `traversal`:

1. **BASELINE** — un XML innocuo (nessun DOCTYPE, un nonce). GUARDIA: se la firma
   di `/etc/passwd` (`root:…:0:0:`) c'è **già** qui, l'endpoint espone quel file a
   prescindere dall'input → non attribuibile al parsing → la lane **tace**.
2. per ogni payload XXE (entità esterna `SYSTEM "file://…"`, più varianti di
   encoding dell'URI e due content-type `application/xml`/`text/xml`), guardo se
   la risposta contiene la firma:
   - **ALTO — VULNERABILE (XXE → file read)**: la firma `root:…:0:0:` compare → il
     parser ha **risolto** l'entità esterna e letto un file di sistema;
   - **ok**: nessuna firma → external-entity processing **disabilitato** (la difesa
     canonica) o l'endpoint non parsa XML.

La firma è il **contenuto** del file, non il riflesso del payload: noi inviamo
`&xxe;` (un *riferimento* a entità), mai il contenuto. Un endpoint che si limita a
rimandare nel corpo il nostro XML riflette `&xxe;` / il DOCTYPE, **mai**
`root:x:0:0:` → nessun falso positivo. **La firma È la guardia**, come il prodotto
calcolato dell'SSTI distingue la valutazione dalla semplice reflection (provato
nel banco avversariale contro `/trap-echo`).

```
python3 aries.py xxe http://127.0.0.1:8099/api/import
python3 aries.py xxe http://host/api/xml --token "$TOKEN" --json
```

Puro Python stdlib (`xml`/`secrets`/`re`), nessuna dipendenza. ATTIVO: manda un
POST XML, solo host in `ALLOWLIST` (il confine vive in `core.probe`); i flag di
**sessione** (`--cookie`/`--token`/`--header`) sono instradati via `core.probe`
(PoC mascherato `$TOKEN`/`$COOKIE`) → un parser XML **dietro il login** (un'API
riservata) è raggiungibile. Il PoC `curl` è costruito dalla stessa richiesta POST
che inietta l'entità. Il benchmark è a due facce (`XXE`): il vuln parsa con le
entità esterne **abilitate** → `file://` risolto → firma presente, il safe
**disabilita** l'external-entity processing → nessuna firma. **Limite onesto:**
copre l'XXE **in-band** con lettura di `/etc/passwd` (la prova deterministica più
solida); le varianti **out-of-band/blind** (entità verso un canary, exfil via
parametro-entità), il bersaglio **Windows** e l'**XInclude** restano fuori dal
modello a singola risposta — provabili separatamente, non assunti.

## SSRF — Server-Side Request Forgery (canary locale out-of-band)

`ssrf` chiede: un parametro che porta una **URL** (webhook, fetcher di immagini,
anteprima link, import-da-URL) viene usato dal server per fare una *richiesta
server-side* verso una destinazione scelta dal client? La prova è **oggettiva e
out-of-band**, l'analogo in-boundary dell'OAST:

1. ARIES avvia un minuscolo **listener canary** su `127.0.0.1:<porta effimera>`
   (quindi dentro l'`ALLOWLIST`, mai un host esterno);
2. inietta nel parametro un URL che punta a quel listener, con un **nonce**
   casuale nel path;
3. guarda se il canary riceve una richiesta che porta il nonce.

- **ALTO — VULNERABILE (SSRF)**: il canary è colpito col nonce → il server ha
  fatto *davvero* la richiesta verso un URL arbitrario scelto dall'attaccante.
- **ok — nessun fetch server-side**: il canary non viene mai contattato → la
  destinazione è validata/bloccata (o il parametro non innesca un fetch).

La prova è il **colpo fisico** ricevuto dal listener, non la risposta del
bersaglio: vale quindi anche per l'**SSRF cieca**. La porta è effimera e il
nonce è casuale per run, così solo chi ha letto l'URL iniettato può colpire il
canary — questo **chiude il falso positivo** dell'endpoint che fa l'**eco**
dell'URL nel corpo (riflette la stringa ma non la richiede): quell'endpoint non
colpisce mai il canary e la lane tace (stessa logica di guardia della `D` del
CSRF).

```
python3 aries.py ssrf 'http://127.0.0.1:8099/fetch?url=X' --param url
python3 aries.py ssrf http://host/webhook --param callback --as json --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda una richiesta al bersaglio, solo
host in `ALLOWLIST` (il canary è un servizio locale, non il bersaglio). Il PoC
`curl` è costruito dalla stessa richiesta di iniezione. Limite onesto: proviamo
che il server segue un URL arbitrario (il cuore dell'SSRF); l'escalation
concreta — metadata del cloud (169.254.169.254), servizi interni, esfiltrazione
— dipende dalla rete del bersaglio e non viene assunta. Il modello è minimale
(una iniezione, un canary): il DNS-rebinding e il redirect-follow restano fuori.

## Path Traversal / LFI

`traversal` chiede: un parametro che porta un **nome di file** (download,
anteprima, include di template) viene usato dal server per leggere un file senza
confinarlo alla radice, così che `../` **esca** e legga file di sistema (Local
File Inclusion / arbitrary file read)? La prova è **oggettiva**: iniettiamo
payload di traversal che puntano a un file di sistema noto e cerchiamo nella
risposta la sua **firma** — il *contenuto* del file, non il riflesso del payload.
La lane prova **due bersagli**, perché la firma dipende dall'OS del server:

- **Unix `/etc/passwd`** → firma una riga `root:…:0:0:`.
- **Windows `\windows\win.ini`** → firma una sezione INI canonica
  `[fonts]`/`[extensions]`, con payload a **separatori backslash** (`..\`).
- **`php://filter` → source disclosure** → molte app PHP fanno
  `include($_GET['page'])`: un include *normale* **esegue** lo script (niente
  sorgente a video), ma il wrapper
  `php://filter/convert.base64-encode/resource=index.php` forza lo stream a
  restituire la **sorgente** del file codificata in **base64**, che l'attaccante
  decodifica offline (tipico per leggere `config.php` con le credenziali). Qui la
  firma non è il contenuto di un file di sistema ma un **blob base64 che
  decodifica a sorgente PHP** (`<?php`): la lane scandisce i run base64 della
  risposta, li decodifica e cerca il tag di apertura PHP.
- **`data://` wrapper → RCE** → sullo stesso `include($_GET['page'])`, con
  `allow_url_include=On`, il wrapper
  `data://text/plain;base64,<payload>` fa **includere ed eseguire** dal server
  uno stream scelto dall'attaccante: la file inclusion diventa **esecuzione di
  codice**. La firma non è un file né una sorgente, ma il **prodotto calcolato**
  di una piccola espressione PHP incorporata nello stream
  (`<?php echo 'marker'; echo 887*883; ?>`): se la risposta contiene
  `marker783221` il server ha **eseguito** il codice. Un endpoint che si limita a
  riflettere la stringa `data://…` (anche decodificando il base64) non produce
  mai il prodotto → la **valutazione è la guardia** anti falso positivo, identica
  nello spirito a quella dell'SSTI. Onesto: il tool prova la *valutazione* (RCE
  via wrapper), l'escalation concreta dipende dalla configurazione PHP del
  bersaglio (`allow_url_include`).

Un endpoint che si limita a riflettere la stringa `../../etc/passwd` non produce
mai `root:x:0:0:` (né `[fonts]`, né un base64 che decodifica a `<?php`, né il
prodotto `marker783221` del data://) → la firma **è** la guardia anti falso
positivo (come il prodotto calcolato dell'SSTI distingue la valutazione dalla
reflection).

**Troncatura NUL-byte (`%00`) legacy.** Alcuni file-server servono solo un tipo
(`.pdf`, `.jpg`) e **appendono** l'estensione al nome del client; se la stringa
finisce in una `open()` C (PHP/Perl vecchi), un **NUL** la tronca prima
dell'estensione. La batteria include quindi varianti `…/win.ini%00.jpg` che
scoprono il file vero scartando l'estensione appesa — l'unico payload che bypassa
un server del genere.

Prima di iniettare, una **baseline** con un nome di file innocuo (nonce casuale):
se una firma compare **già lì**, l'endpoint espone quel file a prescindere dal
nostro input → non è attribuibile al parametro → la lane **tace** (seconda
guardia, come la `D` del CSRF).

- **ALTO — VULNERABILE (Path Traversal)**: un payload fa comparire la firma di un
  file di sistema (assente nella baseline) → lettura di un file fuori radice.
- **ALTO — VULNERABILE (RCE → data:// wrapper)**: un payload `data://` fa comparire
  il **prodotto calcolato** del PHP incorporato (`marker783221`) → il server ha
  incluso ed **eseguito** uno stream scelto dall'attaccante.
- **ok — nessun file-read fuori radice**: nessun payload produce una firma (path
  confinato/sanificato, wrapper disabilitati, o il parametro non legge/include file).
- **ok — esposizione non attribuibile**: la firma è già nella baseline → non
  dimostra un traversal del parametro (guardia).

```
python3 aries.py traversal http://127.0.0.1:8099/download --param file
python3 aries.py traversal http://host/preview --param path --as form --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda payload, solo host in `ALLOWLIST`.
Il PoC `curl` è costruito dalla stessa richiesta che inietta il payload vincente
(il NUL viaggia urlencoded come `%00`, non entra grezzo nel referto). Limiti
onesti: la prova assume un file di sistema noto leggibile (`/etc/passwd` su Unix,
`\windows\win.ini` su Windows — le firme `root:…:0:0:`/`[fonts]` sono i segnali
oggettivi standard), oppure — per il bersaglio `php://filter` — uno stack **PHP**
che passa il parametro a un include/file-read via stream e uno script leggibile
(`index.php`/`config.php`); per il bersaglio **`data://`** uno stack **PHP** con
`allow_url_include=On` che include lo stream (è questa la condizione dell'RCE: il
tool prova la *valutazione*, non l'assume ovunque); l'encoding del parametro è
uniforme (urlencode per query/form, JSON per il body) → le evasioni WAF che
giocano col doppio-encoding del parametro non sono modellate (qui si prova il
traversal, non il bypass del filtro perimetrale).

## Server-Side Template Injection

`ssti` chiede: l'input finisce in un **motore di template** che lo *valuta*, o è
solo riflesso come dato? Inietta un **marker casuale** seguito da un'espressione
aritmetica dentro i delimitatori dei vari motori (`{{…}}` Jinja2/Twig/Nunjucks ·
`${…}` Freemarker/JSP-EL · `#{…}` · `<%= … %>` ERB/EJS) e legge la risposta. I
fattori sono distinti e il prodotto (`887*883 = 783221`) non compare nel letterale,
così `marker+prodotto` è inconfondibile. Tre esiti oggettivi:

- **ALTO — VULNERABILE (SSTI)**: la risposta contiene `marker783221`, cioè il
  motore ha **valutato** l'espressione (es. `{{887*883}}` → `783221`). SSTI
  confermata; l'escalation a RCE dipende dal motore/sandbox (onesto: il tool
  prova la *valutazione*, non assume l'RCE).
- **ok — riflessa ma non valutata**: torna il payload **letterale**
  (`marker{{887*883}}`) → semplice reflection, **non** SSTI (la trappola classica
  dei falsi positivi: un canary riflesso crudo non implica un template).
- **ok — non riflessa**: il marker non compare.

```
python3 aries.py ssti 'http://127.0.0.1:8099/pagina?q=X' --param q
python3 aries.py ssti http://host/render --param name --as form --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda payload, solo host in `ALLOWLIST`.
Ogni finding VULNERABILE porta il PoC `curl` costruito dalla stessa richiesta.

## TLS / transport (dominio nuovo)

`tls` ispeziona il **livello di trasporto** del bersaglio — un dominio diverso
da tutte le altre lane (che lavorano sopra HTTP): il **certificato** è valido e
la connessione negozia un **protocollo moderno**? Un certificato **scaduto** fa
rifiutare la connessione ai client (avviso di sicurezza nel browser, servizio
di fatto interrotto) ed è il sintomo tipico di un rinnovo mancato; un protocollo
deprecato (SSLv3 / TLS 1.0 / 1.1) espone a downgrade e cifrari rotti.

Puro Python stdlib (`ssl`/`socket`), **nessuna dipendenza**. La prova è
**oggettiva**: il verdetto di scadenza nasce dal **codice di verifica di
OpenSSL** (`X509_V_ERR_CERT_HAS_EXPIRED`), non da una stringa riflessa — un
endpoint che "somiglia" non può ingannarla (stessa logica della firma del
traversal o del prodotto calcolato dell'SSTI). Due connessioni:

1. **verifica piena** (come un browser): `ssl.create_default_context()` con le CA
   di sistema (o un `--cafile` per una CA interna/self-signed che **fidi**). Se
   l'handshake fallisce con `CERT_HAS_EXPIRED` → **scaduto** (ALTO VULNERABILE);
   `NOT_YET_VALID` → **non ancora valido** (ALTO); altra verifica fallita
   (self-signed, CA sconosciuta, hostname non corrispondente) → **catena non
   verificabile** (MEDIO, reale ma di classe diversa dalla scadenza); se passa →
   leggiamo `notAfter` e segnaliamo se la scadenza è **imminente** (< 15 giorni).
2. **protocollo**: una connessione `CERT_NONE` (completa sempre l'handshake) per
   leggere la **versione negoziata** e il cifrario; < TLS 1.2 → **deprecato** (MEDIO).

```
python3 aries.py tls 127.0.0.1:8443
python3 aries.py tls https://host --json
# CA interna/self-signed che fidi (il bench usa la CA di test bench_certs/ca-bundle.crt)
python3 aries.py tls 127.0.0.1:8443 --cafile mia-ca.pem
```

**Confine:** la lane apre socket **diretti** (non passa da `core.probe`) → il
confine `ALLOWLIST` è imposto **dentro la lane**, con la stessa regola di
`core.probe`, così nessun host esterno viene toccato (un bersaglio fuori
allowlist è rifiutato). Il PoC è `openssl s_client` + `x509 -dates` (il
certificato del server è pubblico, nessun segreto nel referto). Il benchmark a
due facce (`TLS` nel `bench`) usa due server TLS locali con certificati PEM
**statici** committati in `bench_certs/` (vuln = **scaduto**, safe = **valido**,
entrambi col SAN `127.0.0.1`, firmati dalla stessa CA di test → l'unica
differenza di verifica è la scadenza). Limiti onesti: la scadenza/validità della
catena è il segnale oggettivo e benchmarkato; l'enumerazione esaustiva dei
cifrari deboli e del supporto di **ogni** versione di protocollo (un handshake
per versione, e il set effettivo dipende dall'OpenSSL locale del client) è fuori
scope → riportiamo la versione **negoziata**, non tutte quelle accettate.

## GraphQL — introspection, field suggestion, batching, mutation-via-GET/form

`graphql` ispeziona un endpoint GraphQL (transport standard **POST JSON**
`{"query": "..."}`) per cinque debolezze di **configurazione** tipiche, ognuna con
un segnale **oggettivo e strutturato** che un endpoint il quale si limita a
*riflettere* l'input non può produrre — la **struttura** della risposta **è** la
guardia anti falso positivo (come il prodotto calcolato dell'SSTI o la firma del
traversal). `graphql_audit` restituisce i cinque finding; il benchmark riduce al
peggiore (`_worst`, come TLS/JWT).

- **ALTO — `graphql:introspection`**: la query di introspezione
  `{__schema{queryType{name} types{name}}}` restituisce lo **schema completo**
  (ogni tipo e campo dell'API). In produzione è una misconfigurazione: regala
  all'attaccante la mappa dell'intera superficie. Segnale: la risposta è un JSON
  con `data.__schema.queryType.name` (stringa non vuota) **e** `data.__schema.types`
  (lista non vuota) — una **vera** risposta di introspezione, non l'eco della query.
- **MEDIO — `graphql:suggestions`**: anche con l'introspezione **spenta**,
  graphql-js (e motori simili) perdono i nomi dei campi nei messaggi d'errore
  ("Did you mean …"). Una query con un **typo** del meta-campo universale
  `__typename` (`{__typenam}`): se la risposta è un errore GraphQL (`errors[]`)
  il cui messaggio contiene "Did you mean", il server **suggerisce i nomi reali**
  → leak dello schema a introspezione disabilitata. Il segnale è
  **server-generato** (il typo inviato non contiene la frase né il nome esatto).
- **BASSO — `graphql:batching`**: un **array** di N query in una sola richiesta
  HTTP viene eseguito tutto → amplifica il brute-force (aggira i rate-limit
  per-richiesta) e il DoS. Inviamo `[{query},{query},{query}]` e guardiamo se la
  risposta è una **lista di N risultati GraphQL** (ogni elemento un dict con
  `data` o `errors`). Guardia anti-eco: un endpoint che riflette rimanderebbe gli
  elementi inviati `{"query": …}` (chiave `query`, non `data`/`errors`) → tace.
- **MEDIO — `graphql:get-transport`**: una **mutation** (operazione che cambia
  stato) inviata via **`GET ?query=…`** è **forgeable cross-site** — il browser
  allega da solo il cookie di sessione e una GET "semplice" non fa preflight →
  basta un `<img src=…>` sul sito dell'attaccante = **CSRF**. Il transport
  standard è POST JSON; la best practice (OWASP) è **vietare le mutation su GET**
  (le query in sola lettura su GET sono ammesse, per il caching → **non** vengono
  segnalate). Sonda **senza effetti collaterali**: `mutation{__typename}` chiede
  solo il **nome del tipo radice** delle mutation (meta-campo universale, non muta
  nulla). Segnale **oggettivo**: se la risposta è un risultato **eseguito**
  (`data.__typename` stringa non vuota, generata dal server) la mutation è stata
  eseguita via GET → un endpoint che riflette la query-string non può produrre
  quella struttura (la guardia anti-eco, come le altre tre sonde).
- **MEDIO — `graphql:form-transport`**: il **gemello** del transport GET, su un
  altro content-type CORS-"semplice". Il transport standard POST `application/json`
  **non** è semplice → una richiesta cross-site lo fa precedere da un **preflight**
  (argine CSRF implicito); ma un endpoint che esegue le **mutation** anche quando il
  corpo arriva come **`application/x-www-form-urlencoded`** (campo form `query=…`) è
  **forgeable cross-site** col vettore CSRF più classico: un `<form>` ad auto-submit
  sul sito dell'attaccante manda la mutation **senza token** e **senza preflight**
  (il content-type form è semplice), col cookie di sessione allegato dal browser.
  Stessa sonda senza effetti (`mutation{__typename}`) e stesso segnale strutturato
  (`data.__typename` server-generato = mutation eseguita → guardia anti-eco). Best
  practice (OWASP): accettare le mutation **solo** su `application/json`, così il
  preflight scatta e la forgiatura via form semplice è bloccata.

```
python3 aries.py graphql http://127.0.0.1:8099/graphql
python3 aries.py graphql http://host/graphql --token "$TOKEN" --json
```

Puro Python, nessuna dipendenza. ATTIVO: manda query, solo host in `ALLOWLIST`
(il confine vive in `core.probe`). Ogni finding VULNERABILE porta il PoC `curl`
costruito dalla stessa richiesta. Le guardie strutturali sono **non-vacue**:
provato che un endpoint che fa l'**eco a JSON valido** del body (la risposta
contiene letteralmente `__schema` e rimanda l'array del batch) **non** inganna
nessuna delle cinque. Limite onesto: le prime tre debolezze usano il transport
**standard** POST `application/json`; la quarta (`get-transport`) e la quinta
(`form-transport`) provano la sola **CSRF da mutation** sui due transport
CORS-"semplici" — **GET `?query=`** e **POST `application/x-www-form-urlencoded`** —
dove una richiesta cross-site non fa scattare il preflight (le query read-only su
GET sono ammesse e non segnalate; se lo schema non dichiara alcun tipo Mutation la
sonda `mutation{__typename}` non si applica → nessun verdetto, limite onesto). Il
transport `Content-Type: application/graphql` resta fuori scope del modello
minimale. Il batching è classificato **basso** perché è una *capability* da
limitare, non sempre uno sfruttamento diretto; introspection e suggestion sono
leak concreti dello schema; la mutation-via-GET è una porta **CSRF** concreta.

## Categoria OWASP Top 10 2021 sui findings

Ogni finding porta un'etichetta di **categoria OWASP Top 10 2021** (es.
`A03:2021 Injection`, `A01:2021 Broken Access Control`), derivata in modo
**deterministico** dal nome del `check` — non da un modello, non da un giudizio
a runtime. È una **tassonomia**, non un punteggio: ARIES **non** calcola un CVSS
(darebbe un numero finto — vedi la dottrina), solo la *classe* del problema, per
parlare la lingua standard dei referti e della compliance.

- **`--json`**: ogni finding porta sempre il campo `"owasp"` (vuoto per i check
  generici di tooling, vedi sotto), così un consumatore macchina può filtrare o
  aggregare per categoria.
- **testo**: il tag compare sui soli finding **"da guardare"**
  (crit/high/med/low) — è lì che serve al triage; sugli `ok`/`info` sarebbe rumore.
- **referto** (`--report`): il tag è una riga di ogni finding, in Markdown e HTML.

```
python3 aries.py cors http://127.0.0.1:8099/api --json | jq '.findings[].owasp'
# "A01:2021 Broken Access Control"
```

Mappatura (per prefisso del check): injection (`sqli`/`xss`/`stored-xss`/
`dom-xss`/`ssti`/`nosqli`) → **A03**; access control (`idor`/`cors`/`csrf`/
`mass-assign`/`redirect`/`traversal`/`exposure`/`*-gate`) → **A01**; `race` → **A04**
(Insecure Design); header/cookie/banner/`graphql` → **A05** (Security Misconfiguration);
`tls` → **A02** (Cryptographic Failures, debolezze del trasporto);
`deps` → **A06**; `auth`/`jwt` → **A07**; `ssrf` → **A10**.

Limiti onesti: le categorie OWASP si **sovrappongono** per natura; dove la scelta
è un giudizio (JWT fra crypto e identità → A07 perché l'impatto è la forgiatura
del token; `mass-assign` → A01; `exposure` → A01 per CWE-200/538 dal 2021) la
mappa è un **best-effort documentato**, non una verità assoluta. I check
**generici** (`sast`, `secrets`, `nuclei`, `discover`, `fuzz`, `openapi:spec`)
restano **senza** tag: il loro output è di classe mista o informativo e dargli
una sola categoria sarebbe disonesto. Un **self-check deterministico** in `aries
bench` verifica che ogni finding reale "da guardare" (lane attive **+** il
comando `check`) sia categorizzato e che i check generici restino vuoti — non è
una lane, quindi non entra nel punteggio `/N`.

## Referto condivisibile

`scan --report FILE` scrive un **referto** dei findings da passare a qualcuno
(ticket, allegato, pagina da aprire nel browser). Puro Python, nessuna
dipendenza. Il formato si sceglie dall'**estensione**: `.md`/`.markdown` →
Markdown, `.html`/`.htm` → HTML autoconsistente (CSS inline, niente CDN né JS),
`.sarif`/`.sarif.json` → **SARIF 2.1.0** (vedi sotto), `.xml`/`.junit.xml` →
**JUnit XML** (vedi sotto); qualunque altra estensione → Markdown (default
esplicito).

```
python3 aries.py scan http://127.0.0.1:8099/app --active --report referto.md
python3 aries.py scan ./repo --report referto.html
python3 aries.py scan http://host/app --report out.sarif        # SARIF → GitHub code scanning
python3 aries.py scan http://host/app --report out.xml          # JUnit → runner CI (test rossi)
python3 aries.py scan http://host/app --report out.md --json   # --json: anche l'oggetto porta {"report": {...}}
```

I findings sono **raggruppati per severità** (dal più grave), e ogni finding
porta dentro il suo **PoC `curl`** (il campo `repro`, con il Bearer già
mascherato `$TOKEN`). Il referto è solo **presentazione**: non inventa verdetti
né severità, riprende esattamente i fatti prodotti dalle lane, più il blocco
sentinella (nuovi/risolti/invariati) quando c'è uno scan precedente. L'HTML
fa l'escape di evidenze e PoC, così un payload XSS nel referto resta testo e non
rompe la pagina. `aries bench` include un **self-check** del referto (i PoC
compaiono nel documento, i gruppi di severità sono ordinati) — non entra nel
punteggio delle lane (il `/N` del `bench`) perché è una feature di output, non una lane.

### SARIF 2.1.0 — ingestione in GitHub code scanning

Un referto con estensione `.sarif` (o `.sarif.json`) è scritto in **SARIF
2.1.0**, il formato standard OASIS che **GitHub code scanning**, Azure DevOps e
molti aggregatori ingeriscono. Esportarlo porta i findings di ARIES nel
**Security tab** di un repo e in qualunque pipeline SARIF-aware — è **portata e
usabilità**, non un nuovo fatto: come il resto del referto è **sola
presentazione** (verdetti e severità restano quelli delle lane). Puro Python
(stdlib `json`), nessuna dipendenza.

```
python3 aries.py scan http://127.0.0.1:8099/app --active --report out.sarif
# in un GitHub Action, poi:  github/codeql-action/upload-sarif@v3  con  sarif_file: out.sarif
```

Scelte **oneste** (dottrina):

- **Nessun CVSS inventato.** GitHub userebbe la proprietà `security-severity` (un
  numero 0–10) per il bucket Critical/High/… → sarebbe un numero finto. ARIES
  **non** la emette: la severità **categoriale** di ARIES è mappata sul `level`
  SARIF, anch'esso categoriale — `crit`/`high` → **error**, `med`/`low` →
  **warning**, `info` → **note**. La label originale resta in
  `properties.ariesSeverity`.
- **`ok` non è un risultato.** Un controllo **passato** non è un'osservazione: in
  SARIF un `result` è un problema, non la sua assenza → un bersaglio **pulito**
  produce **zero** risultati (verde nel Security tab), che è esattamente giusto.
- **PoC incluso e mascherato.** Il `curl` che riproduce il finding va in
  `properties.repro` (già mascherato `$TOKEN`/`$COOKIE` dalle lane → nessun
  segreto nel referto).
- **Dedup fra run.** Ogni risultato porta `partialFingerprints.ariesCheckTarget`
  = `check|target` (la **stessa** impronta della sentinella/findings-DB) → GitHub
  riconosce lo stesso problema fra run successivi. Le regole (`rules`) sono
  deduplicate per **prefisso** del check (`sqli:username` + `sqli:password` → una
  sola regola `sqli`).
- **Regole arricchite — tassonomia + rimedio.** Ogni regola porta la
  **tassonomia** della debolezza e una guida di **rimedio**, sempre fatti
  oggettivi (nessuna severità inventata):
  - il tag **OWASP 2021** (`A03:2021 Injection`, …), quando il check ha una
    classe univoca;
  - i tag **CWE** `external/cwe/cwe-NNN` (la convenzione che GitHub code scanning
    legge per mostrare la debolezza sull'alert, stile CodeQL): `sqli` → CWE-89,
    `traversal` → CWE-22/98, `xfo-clickjack` → CWE-1021, … (gli stessi numeri già
    documentati accanto alla mappa OWASP). **Onestà:** una lane a output
    **eterogeneo** — `graphql` (introspection/CSRF/DoS), `deps` (una CWE diversa
    per ogni CVE) — resta **senza** CWE univoca, come resta senza una sola
    categoria OWASP: assegnargliene una sarebbe disonesto;
  - una guida di **rimedio** per regola in `rule.help.text` (mostrata nel
    pannello dell'alert): cosa la lane dimostra e come si corregge.

La funzione `report.to_sarif` è **pura** (nessun I/O, nessuna rete →
deterministica), appoggiata a `core.cwe_ids` (pura, gemella di
`core.owasp_category`); `aries bench` le copre con un **self-check** (`SARIF`):
involucro valido e serializzabile, `ok` escluso, mappa severità→`level` esatta,
nessun `security-severity` numerico, `ruleIndex`/location/fingerprint coerenti,
PoC mascherato, **ogni regola con help di rimedio + tag CWE coincidenti con
`core.cwe_ids`** (e `graphql`/`deps` eterogenei senza CWE univoca) — non entra
nel punteggio delle lane (è output, non una lane).

### JUnit XML — i findings come test in un runner CI

Un referto con estensione `.xml` (o `.junit.xml`) è scritto in **JUnit XML**, lo
standard de-facto che i runner CI (**GitHub** via un test-reporter, **GitLab**,
**Jenkins**, **CircleCI**, …) ingeriscono per mostrare «N passati / F falliti».
Dove il SARIF alimenta il *Security tab*, il JUnit alimenta il **pannello dei
test** della pipeline: ogni **vulnerabilità** diventa un **test fallito** (rosso)
accanto al codice. È **portata e usabilità**, non un nuovo fatto: come il resto
del referto è **sola presentazione** (verdetti e severità restano quelli delle
lane). Puro Python (stdlib `xml.etree.ElementTree` → XML sempre ben formato,
nessuna dipendenza).

```
python3 aries.py scan http://127.0.0.1:8099/app --active --report out.xml
# in un GitHub Action, poi un test-reporter (es. dorny/test-reporter) con  path: out.xml
```

Mappa **onesta** severità→esito (categoriale, **nessun CVSS inventato**):

- ogni finding è un `<testcase>` (il `classname` è il **prefisso** del check —
  `sqli:username` + `sqli:password` → classe `sqli`, come il `ruleId` SARIF; il
  `name` è `check — target`);
- un **problema** (`crit`/`high`/`med`/`low`, "da guardare") → un `<failure>` →
  **test ROSSO** nel runner; `message` è il verdetto, `type` è l'etichetta
  **categoriale** (`CRIT`/`ALTO`/…, mai un numero CVSS), e il corpo porta
  prova/nota/**PoC `curl`** (già mascherato `$TOKEN`/`$COOKIE`);
- un `info` (osservazione) → `<skipped>` (né passato né fallito);
- un `ok` (controllo **passato**) → `<testcase>` **senza figli** → test verde. A
  differenza del SARIF (dove `ok` **non** è un risultato), qui i passaggi hanno
  senso: un test-report documenta anche **cosa è stato controllato** (copertura).
  Un bersaglio **pulito** → `failures=0` → **pipeline verde**.

Tutto è **XML-escapato** da ElementTree → un payload `<script>` nell'evidenza
resta **testo**, non rompe il documento (come l'escaping dell'export HTML). La
funzione `report.to_junit` è **pura** (nessun I/O/rete → deterministica);
`aries bench` la copre con un **self-check** (`JUNIT`): XML ben formato, mappa
severità→esito esatta, conteggi (`tests`/`failures`/`skipped`/`errors`) coerenti,
`type` categoriale (nessun CVSS), PoC mascherato nel corpo, payload XSS escapato,
bersaglio tutto-`ok` → `failures=0` — non entra nel punteggio delle lane (è
output, non una lane).

## Andamento nel tempo (`history` — dashboard read-only dalla findings-DB)

Ogni `scan` salva i suoi findings nella **findings-DB** (`aries.db`, SQLite
stdlib) ed è ciò che rende ARIES una **sentinella**: ma la sentinella confronta
solo con lo scan **immediatamente precedente**, dentro l'output di quel singolo
scan. `history` apre la memoria completa: legge **tutti** gli scan di un
bersaglio e ne mostra l'**andamento nel tempo** — niente rete, nessun payload,
**sola lettura** (non lancia lane, non tocca il DB).

```
python3 aries.py history http://127.0.0.1:8099/app
python3 aries.py history http://127.0.0.1:8099/app --report andamento.html
python3 aries.py history ./repo --json
```

Due viste:

- **Serie degli scan** (dal più vecchio): per ciascuno quando è stato fatto,
  quanti problemi «da guardare» / info / ok, e il delta **🆕 nuovi / ✅ risolti**
  rispetto al precedente (la stessa fingerprint `check|target` e la stessa
  definizione di «problema» — crit/high/med/low — della sentinella; gli `ok`/
  `info` non sono problemi).
- **Problemi con la loro ETÀ**: un record per ogni problema mai comparso —
  gravità (l'**ultima** osservata, perché può cambiare nel tempo), **da quando è
  aperto** (`first_seen`), in **quanti scan** è stato visto, e se è **ancora
  aperto** o **risolto** (presente o no nell'ultimo scan). Ordinati: prima gli
  aperti, poi per gravità.

Il formato di `--report` si sceglie dall'estensione (`.md`→Markdown, `.html`→
HTML autoconsistente, CSS inline, niente CDN/JS — come il referto). Il cuore del
calcolo è una funzione **pura** (`findings_db.timeline`): nessuna rete, nessun
DB, prende la lista ordinata di scan e deriva fatti deterministici → coperta da
un **self-check** in `aries bench` (`HISTORY`, non è una lane → non entra nel
punteggio `/N`, come il referto e i gate) che verifica le invarianti su scan
sintetici (new/fixed come la sentinella, `ok`/`info` non problemi, gravità
ultima osservata, `open`/`resolved` dall'ultimo scan, anzianità tracciata). È
**presentazione**: non inventa verdetti né severità, rende solo gli scan già
salvati. Onesto: la finestra è la storia locale di **quel** bersaglio (chiave
esatta `check|target`); un bersaglio mai scansionato → la dashboard lo dichiara,
senza errori.

**Sparkline dell'andamento (grafico inline nel report HTML).** La tabella «Serie
degli scan» dà i numeri; il report **HTML** aggiunge sopra di essa una
**sparkline SVG inline** (niente JS, niente CDN, niente immagini esterne) del
conteggio dei problemi «da guardare» per scan — il debito sale o scende? La
geometria è una funzione **pura** (`report.sparkline_points`): dai conteggi, nel
loro ordine temporale, ai punti `(x,y)` della polyline — x uniformi dal primo
scan (sinistra) all'ultimo (destra), y **invertita** e scalata sul massimo (un
conteggio più alto sta più in alto, «la linea sale = più problemi»; zero sta
sulla base). Con **meno di 2 scan** non c'è andamento da mostrare → nessuna
sparkline (la tabella basta); il **Markdown** non la include. Deterministica e
testabile senza render, è coperta dal **self-check** `SPARKLINE` in `aries bench`
(non una lane → non entra nel punteggio `/N`, come `HISTORY`/il referto/i gate):
asserisce sulla geometria (N punti, x uniformi e crescenti ai bordi, y
invertita/scalata, tutto-zero piatto) e sul render (<2 scan nessun `<svg>`, ≥2 un
`<svg>` con `<polyline>` nel report HTML).

**Parco macchine (vista multi-bersaglio).** `history` guarda **un** bersaglio;
**senza argomento** mostra invece il **parco macchine** — **tutti** i bersagli
della findings-DB in una sola vista, l'ultimo stato e la tendenza di ciascuno:

```
python3 aries.py history                     # panoramica di tutti i bersagli
python3 aries.py history --report parco.html # una pagina sola (HTML o .md)
python3 aries.py history --json
```

Per ogni bersaglio: quando è stato visto l'**ultimo** scan, quanti **problemi
aperti**, la **gravità peggiore** fra gli aperti e la **tendenza** del conteggio
«da guardare» rispetto allo scan precedente (`▲ peggiora` / `▼ migliora` /
`▬ stabile` / `· 1° scan`, col `+N`/`−N`) e i 🆕/✅ dell'ultimo scan. I bersagli
**più a rischio stanno in cima** (per gravità peggiore, poi per numero di aperti);
i puliti vanno in fondo. Come `history`, è **sola lettura** (niente rete, niente
lane, non tocca il DB): rende solo gli scan già salvati — `worst` guarda i soli
problemi **ancora aperti** (un problema più grave ma risolto non alza l'allarme).
Il cuore è la funzione **pura** `findings_db.fleet` (prende un record
`{target, scans}` per bersaglio e deriva fatti deterministici), coperta dal
**self-check** `FLEET` in `aries bench` (non una lane → non entra nel punteggio
`/N`, come `HISTORY`/`SPARKLINE`/il referto/i gate): verifica ordinamento,
`worst` sui soli aperti, `trend`/`delta`, il bersaglio senza scan saltato e il
render della tabella HTML. Onesto: un bersaglio mai scansionato non compare (non
è nel DB); DB vuoto → lo dichiara, senza errori.

## Gate di CI (`--fail-on` assoluto · `--fail-on-new` di regressione)

`scan --fail-on <sev>` trasforma lo scan in un **gate di pipeline ASSOLUTO**:
dopo aver stampato i findings, se ne esiste almeno uno a quella severità **o più
grave**, ARIES esce con **codice 1** — e GitHub/GitLab fanno fallire il job.
Senza `--fail-on` lo scan **non esce mai** con errore (resta un referto
informativo).

La soglia è inclusiva e monotòna (`crit ⊆ high ⊆ med ⊆ low`): sceglila col
rischio che accetti.

```
python3 aries.py scan http://127.0.0.1:8099/app --active --fail-on high
echo $?    # 1 se c'è un finding ≥ ALTO, 0 altrimenti
```

- **exit 0** — nessun finding alla soglia o più grave (oppure `--fail-on` assente).
- **exit 1** — gate scattato: almeno un finding ≥ soglia (ne stampa l'elenco).
- **exit 2** — errore d'uso di argparse (es. soglia non valida): distinto dal gate.

### `--fail-on-new <sev>` — gate di sola regressione

Il gate assoluto fallisce su **tutto** il debito ≥ soglia, compreso quello
legacy: adottarlo su un progetto reale significa dover prima azzerare l'arretrato.
`scan --fail-on-new <sev>` è il gate **di regressione** complementare: esce con
**codice 1 solo se compare un finding NUOVO** (rispetto all'ultimo scan della
**sentinella**) a quella severità o più grave. Il debito preesistente **non
conta** — così una pipeline può pretendere "niente nuove regressioni" senza
dover prima sanare tutto l'arretrato.

```
python3 aries.py scan http://127.0.0.1:8099/app --active --fail-on-new high
echo $?    # 1 solo se è comparso un finding NUOVO ≥ ALTO
```

- **primo scan** di un bersaglio → salva la baseline e **non scatta** (non c'è
  nulla con cui regredire; sarebbe il gate assoluto).
- **scan successivi** → scatta (exit 1) solo sui finding che la sentinella marca
  come **nuovi**; i persistenti (debito) e i risolti sono inerti.

I due flag sono indipendenti e componibili: se **uno qualunque** dei due scatta,
l'exit è 1 (es. `--fail-on crit --fail-on-new high`: "mai un CRIT, e nessuna
regressione ≥ ALTO").

In `--json` l'oggetto porta `"fail_on": {threshold, tripped, count}` e
`"fail_on_new": {threshold, tripped, count, first_scan}`, così l'esito di ogni
gate è ispezionabile senza parsare il testo. Le decisioni sono pure
(`core.gate` e `core.gate_new`, nessuna rete) e coperte da **self-check
deterministici** in `aries bench` (monotonìa delle soglie e `info`/`ok` inerti
per l'assoluto; per la regressione: scatta solo sui nuovi, il debito
preesistente e la baseline restano inerti) — come il referto, non sono lane,
quindi non entrano nel punteggio `/N`.

Esempio completo di **GitHub Action** (checkout dell'app + avvio su localhost +
gate + upload del referto) in [`ci/github-action-aries-gate.yml`](ci/github-action-aries-gate.yml).

## Impacchettamento (`pip install -e .`)

`pyproject.toml` dà ad ARIES un **entry-point console**: dopo

```
pip install -e .
```

il comando è `aries <comando>` da qualunque directory, non più
`python3 ~/aries/aries.py <comando>`. Il nucleo resta **solo stdlib** (nessuna
dipendenza di runtime); gli strumenti opzionali sono **extra**:

```
pip install -e '.[yaml]'      # spec OpenAPI in YAML (pyyaml)
pip install -e '.[browser]'   # lane dom-xss (poi: playwright install chromium)
```

L'install **editabile** è quella supportata: ARIES ha un layout *flat* (moduli
top-level) e risolve i suoi dati (`wordlists/`, `bench_specs/`) relativamente al
proprio `__file__`; editabile, i moduli restano nel repo e i dati si trovano. Un
install non editabile copierebbe i `.py` in `site-packages` senza i dati →
fuori scope (dichiarato onestamente). Validato su Python **3.9/3.11/3.12/3.13**.

## Dipendenze

- **Nucleo:** solo stdlib Python (nessuna dipendenza).
- **Lane che orchestrano strumenti:** `gitleaks`, `semgrep`, `trivy`, `nuclei`, `ffuf`.
- **dom-xss:** Playwright + Chromium (`pip install playwright && playwright install chromium`).
- **openapi:** gli spec JSON non hanno dipendenze; per gli spec YAML serve `pyyaml` (`pip install pyyaml`).
- **Interprete opzionale:** Ollama (es. `qwen2.5:14b`) via `scan --explain`.

## Limiti onesti

- I **logic-flaw inediti** non si automatizzano: il tool segnala candidati (es. la race), il giudizio resta umano.
- L'**interprete LLM** è opzionale e **debole sul triage**, misurato: i fatti restano del codice.

---

Uso **solo autorizzato**, sulla propria infrastruttura e su lab di cui si ha il permesso.

## Licenza

[MIT](LICENSE) © ManusTheGallicPlague
