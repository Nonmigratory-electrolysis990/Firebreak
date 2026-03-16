# FIREBREAK

### The Security MCP — Pen Testing & Best Practices as AI Tools

**Product Requirements Document — v2.0**
**Marzo 2026**

| | |
|---|---|
| **Tipo** | Open Source (AGPLv3) + Cloud Plan |
| **Target** | Dev, Team, Security Auditor |
| **Architettura** | MCP-First |
| **Deploy** | Self-Hosted / Cloud-Hosted |
| **Status** | Draft — Fase di Design |

---

## 1. Executive Summary

Firebreak è un MCP server di sicurezza che trasforma qualsiasi AI MCP-compatibile in un penetration tester e security advisor. Non è un tool che il developer usa direttamente — è un **toolkit che l'AI usa per te**. Colleghi Firebreak a Claude (o qualsiasi client MCP), e l'AI può: consultare best practices di sicurezza, lanciare penetration test, analizzare codice e configurazioni, e guidarti nel fix — tutto dalla conversazione.

> **🔥 Proposta di Valore Unica**
>
> Dici a Claude "testa la sicurezza della mia app" e Claude chiama i tool Firebreak per fare recon, lanciare attacchi, analizzare i risultati, e suggerirti i fix. Non devi imparare una CLI. Non devi leggere un report. L'AI fa tutto e ti spiega cosa ha trovato in linguaggio naturale.

Due modalità di deployment:

- **Self-Hosted (Free, Open Source):** Installi Firebreak sul tuo server. I test girano sulla tua macchina. Zero dati escono. Ideale per chi vuole controllo totale.
- **Cloud-Hosted (Paid, SaaS):** Un VPS pre-configurato con tutto il necessario: headless browser, port scanner, proxy, AI pipeline. Colleghi l'MCP endpoint e sei operativo in 30 secondi. Ideale per chi non vuole gestire infrastruttura.

**Il problema:** Le app generate da AI hanno vulnerabilità predicibili — auth inconsistente, IDOR, RLS permissive, business logic rotta. I developer non sanno testarle, i tool esistenti non sono pensati per il vibe coding, e i pen test manuali costano troppo.

**La soluzione:** Un MCP server che dà all'AI tutti gli strumenti per fare pen testing e consulenza di sicurezza. L'AI diventa il tuo security team.

---

## 2. Vision e Contesto Strategico

### 2.1 Vision Statement

Trasformare ogni conversazione con un AI in una sessione di security review, rendendo il penetration testing e le best practices di sicurezza accessibili tramite linguaggio naturale.

### 2.2 Perché MCP-First

L'approccio tradizionale (CLI, dashboard, report) ha un problema fondamentale: **richiede che il developer sappia cosa cercare**. Ma chi fa vibe coding spesso non ha competenze di sicurezza — non sa nemmeno che dovrebbe testare le RLS o verificare l'auth su ogni endpoint.

Con l'architettura MCP-first, il flusso si inverte:

- **Prima (CLI-first):** Il developer deve sapere che comando lanciare, interpretare il report, capire i fix.
- **Ora (MCP-first):** Il developer dice "è sicura la mia app?" e l'AI orchestra tutto — recon, test, analisi, spiegazione, fix.

L'AI diventa l'interfaccia. Firebreak diventa il backend di competenza.

### 2.3 Perché Due Piani

| | Self-Hosted | Cloud-Hosted |
|---|---|---|
| **Prezzo** | Gratis (open source) | Paid (subscription) |
| **Setup** | Docker Compose sul tuo server | Collega MCP endpoint, fatto |
| **Dove girano i test** | Sulla tua macchina | Su VPS Firebreak |
| **Dati** | Mai escono dal tuo server | Transitano sul VPS (encrypted in-transit, non persistiti) |
| **Headless browser** | Devi installare Chromium | Pre-installato |
| **Port scanner** | Devi aprire le porte uscenti | Pre-configurato |
| **AI model** | Porti la tua API key | Incluso nel piano |
| **Target** | Privacy-sensitive, enterprise | Indie hacker, team veloci |
| **Limiti** | Nessuno | Scan/mese basati sul piano |

### 2.4 Target Audience

| Segmento | Priorità | Pain Point | Piano |
|---|---|---|---|
| Indie Hacker / Solopreneur | P0 | Non sa cosa testare, vuole zero setup | Cloud-Hosted |
| Team Piccoli (2–10 dev) | P1 | Vuole integrare security nel workflow AI | Cloud o Self-Hosted |
| Security Auditor / Freelancer | P1 | Vuole automatizzare la parte ripetitiva | Self-Hosted |
| Aziende Privacy-Sensitive | P2 | Zero dati fuori, compliance | Self-Hosted |

---

## 3. Principi di Prodotto

1. **MCP-First, Everything Else Second** — L'MCP server è il prodotto. La CLI è un tool di admin. Il dashboard è un viewer. Ma l'interfaccia principale è la conversazione AI.

2. **AI as the User** — I tool sono progettati per essere usati dall'AI, non dall'umano. Le descrizioni sono ottimizzate per il context window. I risultati sono strutturati per il reasoning AI.

3. **Two Worlds, One Experience** — Che tu usi self-hosted o cloud, l'esperienza MCP è identica. Stessi tool, stessi risultati, stessa qualità. La differenza è solo dove girano i test.

4. **Proof Over Theory** — Ogni vulnerabilità è dimostrata con un exploit funzionante. L'AI non dice "potrebbe esserci un IDOR" — dice "ho cambiato l'ID da 123 a 124 e ho visto l'ordine di un altro utente, ecco la response".

5. **Safe by Design** — Attacchi non-distruttivi. Mai DELETE, DROP, o corruzione dati. Rate limiting integrato. Consent obbligatorio.

---

## 4. Architettura di Sistema

### 4.1 MCP-First Architecture

```
┌──────────────────┐     MCP Protocol      ┌──────────────────────────────┐
│                  │ ◄──────────────────── │                              │
│  Claude Desktop  │                        │      FIREBREAK MCP SERVER    │
│  Cursor          │ ────────────────────▶ │                              │
│  Windsurf        │    Tool Calls          │  ┌────────────────────────┐  │
│  Any MCP Client  │    + Results           │  │   TOOL ROUTER          │  │
│                  │                        │  │                        │  │
└──────────────────┘                        │  │  knowledge_* → KB      │  │
                                            │  │  scan_*      → Engine  │  │
                                            │  │  analyze_*   → Analyzer│  │
                                            │  │  report_*    → Reporter│  │
                                            │  └──────────┬─────────────┘  │
                                            │             │                │
                                            │  ┌──────────▼─────────────┐  │
                                            │  │   EXECUTION ENGINE      │  │
                                            │  │                        │  │
                                            │  │  HTTP Client           │  │
                                            │  │  Headless Browser      │  │
                                            │  │  Port Scanner          │  │
                                            │  │  SQL Analyzer          │  │
                                            │  │  Code Parser           │  │
                                            │  │  TLS Prober            │  │
                                            │  └──────────┬─────────────┘  │
                                            │             │                │
                                            │  ┌──────────▼─────────────┐  │
                                            │  │   RESULTS STORE        │  │
                                            │  │   (SQLite / PostgreSQL)│  │
                                            │  └────────────────────────┘  │
                                            └──────────────────────────────┘
```

**L'AI è l'orchestratore.** Firebreak non decide cosa testare — fornisce gli strumenti. L'AI decide la strategia basandosi su ciò che l'utente chiede e sui risultati che riceve dai tool.

### 4.2 Self-Hosted vs Cloud-Hosted

```
SELF-HOSTED                              CLOUD-HOSTED
┌─────────────────────┐                  ┌─────────────────────────────────┐
│  Your Server        │                  │  Firebreak VPS                  │
│                     │                  │                                 │
│  ┌───────────────┐  │                  │  ┌───────────────┐              │
│  │ Firebreak MCP │  │                  │  │ Firebreak MCP │              │
│  │ Server        │◄─┼── MCP ──────────┼──│ Server        │◄── MCP ──── │
│  └───────┬───────┘  │                  │  └───────┬───────┘              │
│          │          │                  │          │                      │
│  ┌───────▼───────┐  │                  │  ┌───────▼───────┐              │
│  │ Execution     │  │                  │  │ Execution     │              │
│  │ Engine        │  │                  │  │ Engine        │              │
│  │               │  │                  │  │               │              │
│  │ Chromium ✓    │  │                  │  │ Chromium ✓    │              │
│  │ Nmap ✓        │  │                  │  │ Nmap ✓        │              │
│  │ sqlparser ✓   │  │                  │  │ sqlparser ✓   │              │
│  └───────────────┘  │                  │  └───────────────┘              │
│                     │                  │                                 │
│  docker compose up  │                  │  https://your-id.firebreak.dev  │
└─────────────────────┘                  └─────────────────────────────────┘
```

**Cloud-Hosted:** L'utente si registra, riceve un MCP endpoint (`https://your-id.firebreak.dev/mcp`), lo aggiunge a Claude Desktop, e inizia a usarlo. Zero installazione, zero configurazione. Il VPS ha già tutto: Chromium headless, nmap, sqlparser, tree-sitter, proxy chain.

**Self-Hosted:** `docker compose up` crea tutto localmente. L'MCP endpoint è `http://localhost:9090/mcp` (o esposto tramite tunnel/reverse proxy).

### 4.3 Componenti Core

| Componente | Responsabilità | Tecnologia |
|---|---|---|
| MCP Server | Protocol handling, tool routing, auth | Rust (Axum) + MCP SDK |
| Knowledge Base | Best practices, VCVD patterns, fix templates | Markdown + JSON, embedded |
| Recon Module | Endpoint discovery, fingerprinting, header analysis | Rust (reqwest, trust-dns) |
| HTTP Attacker | Request crafting, response analysis, exploit execution | Rust (hyper) |
| Browser Engine | XSS testing, CSRF testing, client-side analysis | Headless Chromium (chromiumoxide) |
| Network Scanner | Port scanning, TLS analysis, service detection | Rust (trust-dns, rustls) |
| Code Analyzer | AST parsing, pattern matching, data flow | Rust (tree-sitter) + semgrep |
| SQL Analyzer | RLS policy parsing, query analysis | Rust (sqlparser-rs) |
| Results Store | Scan storage, finding persistence, history | SQLite (self-hosted) / PostgreSQL (cloud) |
| Report Renderer | HTML, PDF, JSON, Markdown export | Rust (Tera templates) |
| Admin API | Dashboard backend, scan management | Rust (Axum) |
| Web Dashboard | Scan viewer, finding explorer, remediation tracker | React + TypeScript |
| Cloud Gateway | Multi-tenant routing, auth, billing, rate limiting | Rust (Axum) + Stripe |

---

## 5. MCP Tool Catalog — Specifica Completa

Questo è il cuore di Firebreak. Ogni tool è progettato per essere chiamato dall'AI, con descrizioni ottimizzate per il context window e risultati strutturati per il reasoning.

### 5.1 Knowledge Tools — "Cosa dovrei sapere?"

L'AI chiama questi tool per consultare best practices prima di scrivere codice o per capire se qualcosa è sicuro.

| Tool | Descrizione per l'AI | Input | Output |
|---|---|---|---|
| `firebreak_best_practice` | Ritorna le best practices di sicurezza per un topic specifico. Usalo quando l'utente chiede come implementare qualcosa in modo sicuro. | `{ topic: "jwt-auth" \| "rls-policy" \| "file-upload" \| "cors" \| "rate-limiting" \| ... }` | Best practice dettagliata con DO / DON'T, codice esempio sicuro, errori comuni AI |
| `firebreak_check_pattern` | Verifica se un pezzo di codice contiene pattern insicuri noti. Usalo quando l'utente mostra codice e chiede se è sicuro. | `{ code: string, language: string }` | Lista di pattern trovati con severity, spiegazione, e fix |
| `firebreak_explain_vuln` | Spiega una vulnerabilità in modo comprensibile. Usalo quando l'utente non capisce un finding. | `{ vuln_id: "VC-AUTH-001" \| "IDOR" \| "XSS" \| ... }` | Spiegazione, come viene exploitata, impatto, come fixarla |
| `firebreak_owasp_check` | Mappa un finding o un pattern all'OWASP Top 10 e CWE. | `{ description: string }` | OWASP category, CWE ID, severity, contesto |
| `firebreak_security_checklist` | Genera una checklist di sicurezza personalizzata per il tech stack dell'utente. | `{ stack: ["nextjs", "supabase", "vercel"] }` | Checklist ordinata per priorità con spiegazioni |

**Esempio di sessione:**

```
Utente: "Sto creando un sistema di auth con JWT in Next.js, come lo faccio sicuro?"

Claude: [chiama firebreak_best_practice con topic="jwt-auth"]
        [chiama firebreak_security_checklist con stack=["nextjs"]]

        "Ecco le best practices per JWT auth in Next.js:

         1. Usa EdDSA (Ed25519) per firmare i JWT, non HS256...
         2. Imposta expiry a massimo 15 minuti con refresh token rotation...
         3. Verifica il JWT in ogni API route con middleware, non solo nel frontend...
         ..."
```

### 5.2 Scan Tools — "Testa la mia app"

L'AI chiama questi tool per eseguire pen test veri. I risultati tornano all'AI che li interpreta e li spiega all'utente.

| Tool | Descrizione per l'AI | Input | Output |
|---|---|---|---|
| `firebreak_scan_full` | Esegue un penetration test completo. Scegli la modalità basandoti su cosa ha condiviso l'utente. | `{ target_url: string, mode: "black" \| "gray" \| "white", source_path?: string, db_connection?: string, credentials?: [...] }` | `{ scan_id: string, status: "running" }` |
| `firebreak_scan_quick` | Scan veloce (2-3 minuti). Solo finding critici e high. Usalo per check rapidi. | `{ target_url: string }` | `{ scan_id, findings: [...top_critical] }` |
| `firebreak_scan_target` | Scan focalizzato su un'area specifica. | `{ target_url: string, focus: "api" \| "auth" \| "rls" \| "frontend" \| "infra" \| "injection", ...options }` | `{ scan_id, status }` |
| `firebreak_scan_status` | Controlla lo stato di uno scan in corso. Chiamalo ogni 30s per scan lunghi. | `{ scan_id: string }` | `{ status, progress_pct, phase, findings_so_far }` |
| `firebreak_scan_stop` | Ferma uno scan in corso. I risultati parziali sono conservati. | `{ scan_id: string }` | `{ stopped: true, partial_results: [...] }` |

**Configurazione opzionale nei tool:**

```json
{
  "target_url": "https://myapp.com",
  "mode": "gray",
  "source_path": "/path/to/project",
  "credentials": [
    { "username": "test@test.com", "password": "test123", "role": "user" },
    { "username": "admin@test.com", "password": "admin123", "role": "admin" }
  ],
  "options": {
    "max_requests_per_second": 10,
    "timeout_seconds": 300,
    "skip_rules": ["VC-FE-007"],
    "targets": ["api", "auth", "rls"]
  }
}
```

### 5.3 Analysis Tools — "Cosa hai trovato?"

L'AI chiama questi tool per esplorare i risultati di uno scan, andare nel dettaglio, e preparare i fix.

| Tool | Descrizione per l'AI | Input | Output |
|---|---|---|---|
| `firebreak_results` | Ritorna il sommario dei risultati di uno scan. Chiamalo dopo che lo scan è completato. | `{ scan_id: string }` | `{ score: "A-F", summary, findings_by_severity, top_risks }` |
| `firebreak_finding_detail` | Dettaglio completo di un finding specifico: evidence, exploit, steps to reproduce. | `{ finding_id: string }` | `{ vuln, severity, evidence: { request, response }, impact, reproduction_steps }` |
| `firebreak_finding_fix` | Genera il codice fix per un finding specifico. Include contesto del framework dell'utente. | `{ finding_id: string, framework?: string }` | `{ fix_description, code_before, code_after, files_to_change }` |
| `firebreak_attack_chain` | Mostra le catene di attacco multi-step scoperte. | `{ scan_id: string }` | `{ chains: [{ steps, total_impact, business_risk }] }` |
| `firebreak_replay` | Riesegue un singolo exploit per verificare se è stato fixato. | `{ finding_id: string }` | `{ still_vulnerable: bool, evidence }` |
| `firebreak_compare` | Confronta due scan per vedere progressi o regressioni. | `{ scan_id_before: string, scan_id_after: string }` | `{ fixed, new, unchanged, score_change }` |
| `firebreak_scan_history` | Lista degli scan precedenti per questo target. | `{ target_url?: string, limit?: number }` | `{ scans: [{ id, date, score, findings_count }] }` |

### 5.4 Report Tools — "Dammi il report"

| Tool | Descrizione per l'AI | Input | Output |
|---|---|---|---|
| `firebreak_report_generate` | Genera un report esportabile in vari formati. | `{ scan_id: string, format: "html" \| "pdf" \| "json" \| "md", include_evidence?: bool, compliance?: ["owasp", "cwe"] }` | `{ report_url: string, download_link: string }` |
| `firebreak_report_executive` | Genera solo l'executive summary per non-tecnici. | `{ scan_id: string }` | `{ summary: string, risk_level, top_3_actions }` |

### 5.5 Configuration Tools — "Configura Firebreak"

| Tool | Descrizione per l'AI | Input | Output |
|---|---|---|---|
| `firebreak_config_get` | Ritorna la configurazione corrente di Firebreak. | `{}` | `{ mode, targets, rate_limit, rules_enabled, ... }` |
| `firebreak_config_set` | Modifica la configurazione. | `{ key: string, value: any }` | `{ updated: true, config }` |
| `firebreak_rules_list` | Lista tutte le regole VCVD disponibili. | `{ category?: string }` | `{ rules: [{ id, name, severity, description }] }` |
| `firebreak_rules_toggle` | Abilita o disabilita una regola specifica. | `{ rule_id: string, enabled: bool }` | `{ updated: true }` |

---

## 6. Vibe Coding Vulnerability Database (VCVD)

Il knowledge base di pattern insicuri specifici del codice AI-generated. Ogni entry è sia una regola di detection che un pezzo di knowledge consultabile dall'AI.

### 6.1 Auth & Identity Patterns

| VCVD ID | Pattern | Severity | AI Pattern |
|---|---|---|---|
| VC-AUTH-001 | Inconsistent Auth Middleware | CRITICAL | L'AI applica auth su alcune route ma non altre |
| VC-AUTH-002 | Client-Only Validation | CRITICAL | Validazione ruolo solo nel frontend |
| VC-AUTH-003 | JWT Not Verified | CRITICAL | `jwt.decode()` senza `verify()` |
| VC-AUTH-004 | Hardcoded Service Key | CRITICAL | `service_role` key nel client-side code |
| VC-AUTH-005 | Missing Token Expiry | HIGH | JWT senza `exp` o con expiry > 30 giorni |
| VC-AUTH-006 | OAuth State Missing | HIGH | OAuth2 senza parametro `state` |
| VC-AUTH-007 | Password in Query Param | HIGH | Password trasmessa via GET |
| VC-AUTH-008 | Session Fixation | MEDIUM | Session ID non rigenerato dopo login |

### 6.2 Data Access Patterns

| VCVD ID | Pattern | Severity | AI Pattern |
|---|---|---|---|
| VC-DATA-001 | Universal IDOR | CRITICAL | ID sequenziali senza ownership check |
| VC-DATA-002 | Permissive RLS | CRITICAL | `USING (true)` su tabelle sensibili |
| VC-DATA-003 | Missing RLS | CRITICAL | Tabella senza RLS abilitato |
| VC-DATA-004 | SELECT * Exposure | HIGH | `SELECT *` che include password hash e PII |
| VC-DATA-005 | Mass Assignment | HIGH | Spread operator senza whitelist campi |
| VC-DATA-006 | GraphQL Introspection | MEDIUM | Schema esposto in produzione |
| VC-DATA-007 | N+1 as DoS | MEDIUM | Query N+1 non limitate |
| VC-DATA-008 | Tenant Isolation Missing | CRITICAL | Multi-tenant senza filtro `tenant_id` |

### 6.3 Injection Patterns

| VCVD ID | Pattern | Severity | AI Pattern |
|---|---|---|---|
| VC-INJ-001 | String Concatenation SQL | CRITICAL | Template literals in query SQL |
| VC-INJ-002 | Reflected XSS | HIGH | User input in HTML senza sanitization |
| VC-INJ-003 | Stored XSS | CRITICAL | User input salvato e renderizzato |
| VC-INJ-004 | Command Injection | CRITICAL | Input in `exec()` / `spawn()` |
| VC-INJ-005 | Path Traversal | HIGH | File path non validato |
| VC-INJ-006 | SSRF | HIGH | URL utente usato in fetch server-side |
| VC-INJ-007 | Template Injection | HIGH | Input in template string server-side |
| VC-INJ-008 | NoSQL Injection | HIGH | Operatori MongoDB in input JSON |

### 6.4 Infrastructure Patterns

| VCVD ID | Pattern | Severity | AI Pattern |
|---|---|---|---|
| VC-INFRA-001 | Debug Mode in Prod | HIGH | `DEBUG=true`, stack traces esposti |
| VC-INFRA-002 | Permissive CORS | HIGH | `Access-Control-Allow-Origin: *` con credentials |
| VC-INFRA-003 | Missing Security Headers | MEDIUM | No HSTS, X-Content-Type-Options, X-Frame |
| VC-INFRA-004 | Open Docker Ports | MEDIUM | Porte non necessarie esposte |
| VC-INFRA-005 | Unencrypted Storage | MEDIUM | File upload senza encryption |
| VC-INFRA-006 | Weak TLS | MEDIUM | TLS 1.0/1.1 abilitato |
| VC-INFRA-007 | Exposed Admin Panel | HIGH | Admin senza IP restriction |
| VC-INFRA-008 | Default Credentials | CRITICAL | Credenziali default non cambiate |

### 6.5 Frontend Patterns

| VCVD ID | Pattern | Severity | AI Pattern |
|---|---|---|---|
| VC-FE-001 | Secrets in Bundle | CRITICAL | API key nel JavaScript bundle |
| VC-FE-002 | Client-Side Auth Guard | HIGH | Route protection solo via Router |
| VC-FE-003 | LocalStorage Tokens | MEDIUM | JWT in `localStorage` |
| VC-FE-004 | Missing CSRF | HIGH | Form senza CSRF token |
| VC-FE-005 | Unvalidated Redirects | MEDIUM | Redirect URL da query param |
| VC-FE-006 | Insecure PostMessage | MEDIUM | `postMessage` senza origin check |
| VC-FE-007 | Source Maps in Prod | LOW | `.map` files accessibili |
| VC-FE-008 | Form Autofill Leak | LOW | Campi sensibili senza `autocomplete="off"` |

---

## 7. Conversational UX — Come l'AI Usa Firebreak

### 7.1 Flussi Tipici

**Flusso 1 — "È sicura la mia app?"**

```
Utente: "Ho deployato la mia app Next.js + Supabase su https://myapp.com,
         puoi controllare se è sicura?"

Claude: Chiamo firebreak per analizzare la tua app.

        [firebreak_scan_quick → { target_url: "https://myapp.com" }]

        Ho fatto un quick scan. Trovate 3 vulnerabilità:

        🔴 CRITICAL — L'endpoint /api/admin/stats è accessibile senza
           autenticazione. Chiunque può vedere le metriche interne.

        🔴 CRITICAL — IDOR su /api/orders/:id. Ho cambiato l'ID da 42 a 43
           e ho visto l'ordine di un altro utente.

        🟡 HIGH — Il JWT ha un expiry di 365 giorni.

        Vuoi che ti mostri come fixare ognuna?

Utente: "Sì, partiamo dall'IDOR"

Claude: [firebreak_finding_fix → { finding_id: "...", framework: "nextjs" }]

        Ecco il fix. Nel tuo file /api/orders/[id].ts, devi aggiungere
        un check di ownership...

        [mostra codice before/after]

        Vuoi che verifichi se il fix funziona?

Utente: "Ho applicato il fix, controlla"

Claude: [firebreak_replay → { finding_id: "..." }]

        ✅ L'IDOR è stato fixato. Ora quando provo ad accedere all'ordine
        di un altro utente ricevo un 403 Forbidden. Perfetto.
```

**Flusso 2 — "Come implemento X in modo sicuro?"**

```
Utente: "Devo implementare file upload nella mia app, come lo faccio sicuro?"

Claude: [firebreak_best_practice → { topic: "file-upload" }]

        Ecco le best practices per file upload sicuro:

        1. Valida il MIME type tramite magic bytes, non solo l'estensione...
        2. Imposta un size limit per file (consiglio 10MB max)...
        3. Rinomina il file con UUID, mai usare il nome originale...
        4. Se usi Supabase Storage, imposta bucket privato con RLS...
        5. Scansiona con ClamAV se accetti file da utenti non verificati...

Utente: "Ecco il codice che ho scritto, è sicuro?"

Claude: [firebreak_check_pattern → { code: "...", language: "typescript" }]

        Ho trovato 2 problemi nel tuo codice:

        🟡 HIGH — Stai usando il nome file originale nel path di storage.
           Un attaccante potrebbe fare path traversal con "../../etc/passwd".
           Fix: usa crypto.randomUUID() come filename.

        🟡 MEDIUM — Non stai validando i magic bytes. Un attaccante potrebbe
           uploadare un .exe rinominato in .jpg.
           Fix: usa il pacchetto 'file-type' per verificare...
```

**Flusso 3 — "Scan profondo con codice sorgente"**

```
Utente: "Ecco il mio progetto [allega ZIP o link repo]. Fai un audit completo."

Claude: [firebreak_scan_full → {
          target_url: "https://myapp.com",
          mode: "gray",
          source_path: "/uploaded/project"
        }]

        Sto lanciando un audit gray-box. Analizzo il codice sorgente
        e testo gli endpoint live. Ci vorranno circa 10 minuti.

        [firebreak_scan_status → polling ogni 30s]

        Progresso: 45% — Ho completato recon e analisi del codice.
        Sto testando 23 endpoint API. Trovati 2 finding finora...

        [scan completo]

        [firebreak_results → { scan_id: "..." }]

        Audit completato. Security Score: D

        Ho trovato 8 vulnerabilità, inclusa una attack chain pericolosa:

        [firebreak_attack_chain → { scan_id: "..." }]

        ⛓️ ATTACK CHAIN: Da utente anonimo ad admin
        Step 1: L'endpoint /api/signup non valida il campo "role" nel body
        Step 2: Creo un account con role: "admin"
        Step 3: Accedo a /api/admin/* con privilegi completi
        Impatto: Full system compromise

        Vuoi il report completo in PDF?
```

### 7.2 Tool Design per AI

Ogni tool è progettato seguendo queste regole:

- **Descrizioni machine-readable:** Ogni tool ha una descrizione che dice esattamente all'AI QUANDO usarlo, non solo cosa fa.
- **Output strutturato:** JSON con campi consistenti. L'AI può ragionare sui risultati senza parsing complesso.
- **Progressività:** L'AI può partire con `scan_quick` e approfondire con `finding_detail` e `finding_fix` solo dove serve.
- **Contesto minimo:** L'AI non deve ricordare stato complesso. Ogni risultato include ciò che serve per il prossimo step.

---

## 8. Cloud-Hosted Architecture

### 8.1 VPS Infrastructure

Ogni Cloud-Hosted instance gira su un VPS isolato con:

| Componente | Dettaglio |
|---|---|
| **OS** | Ubuntu 24.04 LTS (hardened) |
| **Container Runtime** | Docker (rootless mode) |
| **MCP Server** | Firebreak MCP (Rust binary) |
| **Headless Browser** | Chromium 130+ (sandboxed) |
| **Network Tools** | nmap, curl, openssl |
| **Code Parsers** | tree-sitter (multi-language), semgrep |
| **SQL Analyzer** | sqlparser-rs (embedded in Firebreak) |
| **Storage** | PostgreSQL 16 (scan results + tenant data) |
| **Proxy** | Caddy (TLS termination, MCP routing) |
| **Isolation** | Ogni scan gira in un container dedicato con network namespace isolato |

### 8.2 Multi-Tenant Architecture

```
                    ┌──────────────────────────────┐
                    │        CLOUD GATEWAY          │
                    │  (Caddy + Auth + Rate Limit)  │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼─────┐  ┌──────▼───────┐  ┌─────▼────────┐
     │  Tenant A    │  │  Tenant B    │  │  Tenant C    │
     │              │  │              │  │              │
     │  MCP Server  │  │  MCP Server  │  │  MCP Server  │
     │  Exec Engine │  │  Exec Engine │  │  Exec Engine │
     │  SQLite      │  │  SQLite      │  │  SQLite      │
     │              │  │              │  │              │
     │  Isolated    │  │  Isolated    │  │  Isolated    │
     │  Container   │  │  Container   │  │  Container   │
     └──────────────┘  └──────────────┘  └──────────────┘
```

Ogni tenant ha il proprio container isolato. Nessun dato viene condiviso. I risultati degli scan sono encrypted at-rest e automaticamente eliminati dopo 30 giorni (configurabile).

### 8.3 Pricing Model

| Piano | Prezzo | Scan/mese | Modalità | Features |
|---|---|---|---|---|
| **Starter** | $0 | 5 quick scans | Black-box only | Quick scan, knowledge tools, basic report |
| **Pro** | $29/mo | 50 scan (qualsiasi tipo) | Black + Gray + White | Tutti i tool, PDF report, scan history, comparison |
| **Team** | $99/mo | 200 scan, 5 utenti | Tutti | Shared dashboard, CI/CD webhook, priority execution |
| **Enterprise** | Custom | Illimitati | Tutti | Dedicated VPS, SLA, custom VCVD rules, SSO |

### 8.4 Data Privacy (Cloud)

| Aspetto | Policy |
|---|---|
| Scan results | Encrypted at-rest (AES-256-GCM). Auto-delete dopo 30 giorni. |
| Source code | Mai persistito. Analizzato in-memory, eliminato a fine scan. |
| Credentials di test | Mai loggate. Usate solo durante lo scan, poi scartate. |
| Target URL | Loggato per billing/rate limiting. Non condiviso. |
| AI reasoning | Non inviato a terzi. Il reasoning gira sul VPS Firebreak. |
| Network traffic | Encrypted in-transit (TLS 1.3). Zero plaintext. |

---

## 9. Self-Hosted Setup

### 9.1 Quick Start

```bash
# 1. Clone
git clone https://github.com/firebreak/firebreak.git
cd firebreak

# 2. Configure
cp .env.example .env
# Edita .env: imposta ANTHROPIC_API_KEY (opzionale, per knowledge tools avanzati)

# 3. Launch
docker compose up -d

# 4. Connect MCP
# In Claude Desktop settings, aggiungi:
# {
#   "mcpServers": {
#     "firebreak": {
#       "url": "http://localhost:9090/mcp"
#     }
#   }
# }

# 5. Done! Dì a Claude: "Testa la sicurezza di https://myapp.com"
```

### 9.2 Docker Compose Stack

```yaml
services:
  firebreak:
    image: ghcr.io/firebreak/firebreak:latest
    ports:
      - "9090:9090"    # MCP endpoint
      - "9091:9091"    # Dashboard
    volumes:
      - ./data:/data   # Scan results (SQLite)
      - ./config:/config
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - FIREBREAK_MODE=self-hosted
    depends_on:
      - chromium

  chromium:
    image: ghcr.io/firebreak/chromium-headless:latest
    # Sandboxed, no network access except through firebreak

  dashboard:
    image: ghcr.io/firebreak/dashboard:latest
    ports:
      - "9091:80"
    environment:
      - API_URL=http://firebreak:9090
```

### 9.3 Requisiti Minimi (Self-Hosted)

| Risorsa | Minimo | Raccomandato |
|---|---|---|
| CPU | 2 core | 4+ core |
| RAM | 2 GB | 4 GB (Chromium headless è pesante) |
| Storage | 5 GB | 20 GB |
| OS | Linux x86_64 / ARM64 | Ubuntu 22.04+ |
| Docker | 24.0+ | Con Compose v2 |
| Network | Accesso in uscita verso il target | Porte 80, 443 aperte outbound |

---

## 10. Tech Stack Completo

| Layer | Tecnologia | Versione | Ruolo |
|---|---|---|---|
| Language (Core) | Rust | 1.77+ | MCP Server, execution engine, analyzers |
| Language (MCP protocol) | Rust | — | MCP protocol handling via Axum |
| Language (Dashboard) | TypeScript | 5.4+ | React web dashboard |
| HTTP Client | reqwest + hyper | Latest | Request crafting, response analysis |
| Async Runtime | tokio | Latest | Concurrency per scan paralleli |
| SQL Parser | sqlparser-rs | Latest | RLS policy analysis |
| Code Parser | tree-sitter | Latest | Multi-language AST |
| Static Analysis | semgrep (rules) | Latest | Pattern matching |
| Headless Browser | Chromium via chromiumoxide | Latest | Frontend testing |
| TLS Analysis | rustls + webpki | Latest | TLS config probing |
| Network | trust-dns | Latest | DNS + port scanning |
| Local Storage | SQLite (rusqlite) | Latest | Self-hosted scan results |
| Cloud Storage | PostgreSQL 16 | Latest | Cloud tenant data |
| Report Template | Tera | Latest | HTML/PDF generation |
| PDF Export | weasyprint | Latest | PDF rendering |
| Frontend | React + TypeScript + Vite | 19/5.4/6 | Dashboard |
| Frontend Style | Tailwind CSS | 4.0 | Styling |
| Frontend Charts | Recharts | Latest | Trends |
| Gateway (Cloud) | Caddy | Latest | TLS, routing, rate limiting |
| Billing (Cloud) | Stripe | Latest | Subscription management |
| Container | Docker + Compose | Latest | Deployment |
| CI/CD | GitHub Actions | N/A | Build, test, release |

---

## 11. Safety Guardrails

| Regola | Dettaglio |
|---|---|
| **No Destructive Operations** | Mai DELETE, DROP, TRUNCATE, UPDATE su dati non creati da Firebreak |
| **PII Redaction** | Dati sensibili scoperti loggati come `[PII REDACTED]` nel report |
| **Rate Limiting** | Default 10 req/s verso il target. Hard cap 100 req/s |
| **Scope Lock** | Attacca SOLO il target URL specificato. Zero lateral movement |
| **Test Cleanup** | Record di test creati durante lo scan eliminati al termine |
| **Consent** | Primo scan richiede conferma: l'AI chiede "Confermi di avere autorizzazione?" |
| **Audit Trail** | Ogni richiesta HTTP loggata con timestamp, target, motivazione |
| **Container Isolation** | Ogni scan gira in container con network namespace isolato (cloud) |
| **No Data Persistence (Cloud)** | Source code mai persistito. Analizzato in-memory. |

---

## 12. Security Score

| Score | Criterio |
|---|---|
| **A** | Zero CRITICAL o HIGH. Max 2 MEDIUM. |
| **B** | Zero CRITICAL. Max 2 HIGH. Max 5 MEDIUM. |
| **C** | Zero CRITICAL. Max 5 HIGH. |
| **D** | 1–2 CRITICAL o > 5 HIGH. |
| **F** | 3+ CRITICAL o una attack chain che permette full compromise. |

---

## 13. Sinergia con Bastion

| Scenario | Bastion (prevenzione) | Firebreak (validazione) |
|---|---|---|
| RLS misconfiguration | SPE blocca `USING (true)` | Testa che RLS funzionino con query reali |
| Auth bypass | JWT verification obbligatoria | Testa ogni endpoint con token mancante/scaduto |
| Service key exposure | Blocca `service_role` in contesti client | Cerca la key nel JS bundle |
| Privilege escalation | Blocca query che modificano ruoli | Tenta escalation da user a admin |
| Data exposure | Storage encryption + ACL | Tenta accesso a file di altri utenti |

**Workflow combinato via MCP:**

```
Utente: "Crea una tabella ordini e poi testa se è sicura"

Claude: [bastion_create_table → tabella con RLS]
        [bastion_create_policy → policy owner-based]
        [firebreak_scan_target → focus: "rls"]

        ✅ Score A — Le policy sono configurate correttamente.
```

---

## 14. Roadmap di Sviluppo

### Fase 1 — MCP Core (Mesi 1–3)

- MCP Server con protocol handling completo
- Knowledge tools: `best_practice`, `check_pattern`, `explain_vuln`, `security_checklist`
- Scan tools: `scan_quick`, `scan_full` (black-box)
- VCVD v1: top 20 patterns (AUTH, DATA, INJ)
- HTTP attacker engine
- Results store (SQLite)
- Docker Compose self-hosted
- Basic report (JSON + Markdown)
- Safety guardrails completi

### Fase 2 — Full Spectrum (Mesi 4–6)

- Gray-box e white-box mode
- Code analyzer (tree-sitter + semgrep)
- RLS analyzer (sqlparser-rs)
- Frontend scanner (headless Chromium)
- Infrastructure scanner
- VCVD v2: catalogo completo (40+ patterns)
- Web Dashboard v1
- Analysis tools: `finding_detail`, `finding_fix`, `replay`, `compare`
- Report tools: HTML + PDF export
- Attack chain detection

### Fase 3 — Cloud Launch (Mesi 7–10)

- Cloud-hosted infrastructure (VPS provisioning)
- Multi-tenant architecture
- Cloud Gateway (Caddy + auth + billing)
- Stripe integration (Starter/Pro/Team)
- MCP endpoint cloud (`https://your-id.firebreak.dev/mcp`)
- Bastion integration nativa
- CI/CD webhooks
- OWASP + CWE compliance mapping

### Fase 4 — Ecosystem (Mesi 11–12+)

- Enterprise plan (dedicated VPS, SSO, custom rules)
- VCVD community contributions
- Local AI support (Ollama)
- Scheduled scans
- Slack/Discord notifications
- API pubblica
- Plugin system per scanner custom
- Firebreak Playground (app vulnerabile per imparare)

---

## 15. Analisi Competitiva

| Feature | OWASP ZAP | Burp Suite | Snyk | Semgrep | Firebreak |
|---|---|---|---|---|---|
| Open Source | Sì | Parziale | Parziale | Sì | **Sì (AGPLv3)** |
| MCP-Native | No | No | No | No | **Sì (core)** |
| AI Reasoning | No | No | No | No | **Sì** |
| Vibe Coding Patterns | No | No | No | Parziale | **Sì (VCVD)** |
| Black-box | Sì | Sì | No | No | **Sì** |
| Gray/White-box | No | No | Sì | Sì | **Sì** |
| RLS Testing | No | No | No | No | **Sì** |
| Business Logic | No | Manuale | No | No | **Sì** |
| Attack Chains | No | Manuale | No | No | **Sì** |
| Cloud-Hosted | No | Sì ($) | Sì | Sì | **Sì** |
| Self-Hosted | Sì | Sì | No | Sì | **Sì** |
| Fix Suggestions | No | No | Sì | Sì | **Sì** |

---

## 16. Metriche di Successo

| Metrica | Target v1 | Come Misurare |
|---|---|---|
| Detection rate VCVD patterns | > 90% | Test su app vulnerabili note |
| False positive rate | < 5% | Verify phase success |
| Quick scan time | < 3 minuti | Benchmark |
| Full scan time (< 100 endpoint) | < 15 minuti | Benchmark |
| Cloud MCP latency (tool response) | < 2s per knowledge tool | P95 monitoring |
| Cloud subscribers (6 mesi) | > 500 Pro/Team | Stripe metrics |
| Self-hosted installs | > 2,000 | Docker Hub pulls |
| GitHub Stars (6 mesi) | > 3,000 | GitHub metrics |

---

## 17. Rischi e Mitigazioni

| Rischio | Probabilità | Impatto | Mitigazione |
|---|---|---|---|
| Falsi positivi erodono fiducia | Alta | Alto | Verify phase + confidence score |
| Cloud infra costosa per free tier | Media | Alto | Starter limitato a 5 scan/mese, no Chromium |
| Uso malevolo (attaccare siti altrui) | Media | Alto | Consent obbligatorio, audit trail, ToS severi |
| MCP protocol evolve e rompe compatibilità | Bassa | Medio | Abstraction layer MCP interno |
| AI hallucina vulnerabilità | Media | Alto | Ogni finding DEVE avere evidence verificabile |
| Competitor copia l'idea VCVD | Media | Medio | Community-driven, first mover, ecosystem lock-in |

---

## 18. Open Questions

1. Il free tier cloud dovrebbe includere il source code analysis o solo black-box?
2. Firebreak Playground: creare un'app volutamente vulnerabile per demo e learning?
3. Il VCVD dovrebbe essere un repo separato con contribuzioni community via PR?
4. Offrire un "Firebreak Badge" (come i badge coverage) per i repo che passano il scan?
5. Integrazione con bug bounty platforms (HackerOne, Bugcrowd)?
6. Supportare scan di mobile API (iOS/Android)?
7. Creare un "Firebreak for Bastion" plugin che testa automaticamente dopo ogni schema change?

---

## Appendice A — Glossario

| Termine | Definizione |
|---|---|
| **VCVD** | Vibe Coding Vulnerability Database — catalogo di pattern insicuri del codice AI-generated |
| **MCP** | Model Context Protocol — protocollo per connettere AI a tool esterni |
| **IDOR** | Insecure Direct Object Reference — accesso a risorse altrui cambiando un ID |
| **RLS** | Row Level Security — filtro accesso dati a livello riga in PostgreSQL |
| **CVSS** | Common Vulnerability Scoring System — standard per severity delle vulnerabilità |
| **CWE** | Common Weakness Enumeration — catalogo tipi di vulnerabilità |
| **OWASP** | Open Worldwide Application Security Project — standard sicurezza web |
| **XSS** | Cross-Site Scripting — iniezione JavaScript malevolo |
| **CSRF** | Cross-Site Request Forgery — forza azioni non intenzionali |
| **SSRF** | Server-Side Request Forgery — induce il server a fare richieste interne |
| **WAF** | Web Application Firewall — filtra traffico HTTP |

---

*FIREBREAK — Because if you don't test it, someone else will.*
