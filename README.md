# Aegis — Confidential Data Guard for AI Agents

**Aegis is a local Data-Loss-Prevention (DLP) layer that strips confidential company data out
of requests to AI agents (Claude Code, Cursor, Cline, ChatGPT, custom scripts) before they
ever leave the machine, then restores the real values in the response so the developer never
notices.**

> Detection runs entirely on the local machine. No API key is required and no data is ever
> sent to any AI to "check" it. Aegis never reads or stores your agent's API key — it only
> forwards it.

```
   employee's agent                Aegis (localhost)                 AI provider
  +----------------+    request   +------------------+  scrubbed   +--------------+
  |  Claude Code   | -----------> |  detect + redact  | ----------> | api.anthropic |
  |  Cursor / etc. | <----------- |  restore on reply | <---------- |   .com / ...  |
  +----------------+   response   +------------------+   response  +--------------+
                                   real values never cross this line ^
```

---

## Table of contents

- [The problem](#the-problem)
- [Why this beats git-secrets / gitleaks / GitGuardian](#why-this-beats-git-secrets--gitleaks--gitguardian)
- [Interception modes](#interception-modes)
- [Architecture](#architecture)
- [Core engine — UML class diagram](#core-engine--uml-class-diagram)
- [Request lifecycle (sequence)](#request-lifecycle-sequence)
- [Redact / restore decision (flowchart)](#redact--restore-decision-flowchart)
- [Detection pipeline](#detection-pipeline)
- [System proxy and transparent interception](#system-proxy-and-transparent-interception)
- [Prerequisites](#prerequisites)
- [Install and build](#install-and-build)
- [Running Aegis](#running-aegis)
- [Web control panel (GUI)](#web-control-panel-gui)
- [CLI commands](#cli-commands)
- [Configuration](#configuration)
- [VS Code extension](#vs-code-extension)
- [Checking status](#checking-status)
- [Security and privacy](#security-and-privacy)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Roadmap](#roadmap)

---

## The problem

Developers paste `.env` files, config, logs, and proprietary code into AI agents every day.
Tools like git-secrets and gitleaks only scan *commits* — they do nothing about the real leak
path: **the request to the model**. By the time code reaches a commit, it has often already
been sent to a third-party LLM.

Aegis guards exactly that boundary.

```mermaid
flowchart LR
    Dev["Developer"] -->|"pastes secret / code"| Agent["AI Agent"]
    Agent -->|"HTTPS"| Guard{"Aegis<br/>local guard"}
    Guard -->|"scrubbed only"| Cloud["AI Provider"]
    Cloud -->|"response"| Guard
    Guard -->|"restored"| Agent
    Guard -.->|"counts only, no values"| Audit["Audit log"]
    style Guard fill:#1f6feb,color:#fff
    style Cloud fill:#30363d,color:#fff
```

---

## Why this beats git-secrets / gitleaks / GitGuardian

| | git-secrets / gitleaks | GitGuardian / Cyberhaven | Aegis |
|---|:--:|:--:|:--:|
| Catches secrets at **commit** time | Yes | Yes | Yes (`aegis scan`) |
| Scans entire **git history** | Yes | Yes | Yes (`aegis scan-history`) |
| Catches data pasted into **AI agents** | No | No | Yes |
| Scans **AI responses** for new secrets | No | No | Yes |
| Works across **any** agent (not one editor) | No | No | Yes (API + OS level) |
| **Restores** values so the workflow isn't broken | n/a | n/a | Yes |
| Context-aware PII (names, addresses, DOB) | No | Yes (cloud ML) | Yes (local heuristics + optional local NER) |
| Custom company dictionary (codenames, customers) | Partial | Partial | Yes (first-class) |
| **Compliance reports** (PCI/HIPAA/GDPR) | No | Yes | Yes (`aegis report`) |
| **Dashboard / desktop app** | No | Yes (SaaS) | Yes (web + iOS-style app) |
| **Central team policy** | No | Yes (cloud) | Yes (shared policy file) |
| Runs fully **offline**, never phones home | Yes | No (SaaS) | Yes |
| Needs **no API key**, makes no AI calls | Yes | No | Yes |

---

## Enterprise-grade coverage

The gaps that typically separate a local tool from enterprise DLP are closed — without giving
up the offline, no-API-key design:

- **Context-aware PII** — beyond field-regex, a local detector finds person names (bundled
  name list + context), street addresses, dates of birth, IBANs, and passport numbers. For
  higher recall, set `nerCommand` to a local NER model (GLiNER/Presidio) — still offline.
- **Git-history scanning** — `aegis scan-history` walks every blob in the repo's history and
  flags secrets that were committed and later "removed."
- **AI response scanning** — the proxy also scans the model's *output* for newly introduced
  secrets (e.g. a key the AI invented in generated code) and records them as `response` events.
- **Prompt optimization (token savings)** — an optional local compressor loops safe whitespace
  passes until the text stops shrinking, cutting tokens on every request **before it leaves** —
  no AI calls. Savings are recorded per request (`aegis budget`, the activity feed, `aegis
  optimize <file>` to preview). Conservative by default; `aggressive` removes blank lines and
  collapses internal spacing for bigger savings.
- **Token & cost spend control** — per-window token/cost budgets **per service and per employee**,
  enforced at the proxy (block with `429` or warn), with live spend via `aegis budget` and the
  dashboard. Employees are identified by a configurable header, then an API-key fingerprint, then
  the OS user — the key itself is never stored. Usage is read from each provider's `usage` field.
- **Compliance reporting** — `aegis report` aggregates the audit log into PCI DSS, HIPAA, GDPR,
  and a secrets/SOC2 bucket, over an optional `--since` window, as text or JSON.
- **Central team policy** — point `policyFile` (or `AEGIS_POLICY`) at a shared partial config;
  it is merged authoritatively over local settings, so one file governs the dictionary, mode,
  and detectors across every machine.
- **Dashboard & desktop app** — a local control panel (`aegis gui`) and a chromeless desktop
  window (`aegis app`) with live status, a redaction tester, policy editor, and activity feed.
- **RBAC + SSO** — control-plane mutations (change policy, start/stop the guard) require a role.
  Authenticate with static API tokens or a **bearer JWT verified locally** (HS256 shared secret or
  RS256 with your IdP's public key — the Okta/Entra/Auth0 integration point). Roles: `viewer` <
  `operator` < `admin`. Config: `auth`.
- **Fleet management** — run `aegis fleet` as a central collector; each machine reports its rolling
  spend, and the collector aggregates **per host and per employee** across the org (token-authed).
- **MCP security** — MCP (Model Context Protocol) tool calls are recognized; arguments are scrubbed
  like any payload, and a **tool deny-list** (`mcp.deniedTools`) blocks dangerous tools (shell,
  file deletion, …) outright before they reach the server.
- **Local NER bridge** — beyond the built-in name/org/location recognizers, point `nerCommand` at
  [`scripts/ner_presidio.py`](scripts/ner_presidio.py) to add a local **Presidio/GLiNER** model for
  context-aware PII — still fully offline.

**Honest about the differences:** RBAC + JWT/OIDC verification is built in, but Aegis is not a
SAML IdP — it consumes your IdP's tokens rather than replacing it. The bundled recognizers are
local heuristics; a transformer-grade NER runs via the documented `nerCommand` bridge rather than
being shipped inside the npm package (to keep it small and offline). Central policy is a shared
file, not a hosted control plane. These are deliberate trade-offs to stay offline and key-free.

---

## Supported AI services (and adding your own)

Aegis is provider-agnostic. Detection, redaction, and token/cost budgets work across:

| Provider | Request shape | Token usage parsed | Pricing |
|---|---|---|---|
| Anthropic (direct / Bedrock / Vertex) | `anthropic` | input/output_tokens | yes |
| OpenAI | `openai` | prompt/completion_tokens | yes |
| **Azure OpenAI** | `openai` | prompt/completion_tokens | yes (OpenAI model names) |
| **Google Gemini / Vertex** | `gemini` | promptTokenCount/candidatesTokenCount | yes |
| **AWS Bedrock** | passthrough* | input/outputTokenCount | Claude/Llama/Titan |
| Cohere / Mistral / DeepSeek / Groq | passthrough* | provider variants | yes (common models) |
| **Any internal company agent** | passthrough* | best-effort + estimate | per-service budget |

\* "passthrough" means Aegis deep-scrubs **every string** in the body — safe by default, it
over-redacts rather than leak. Add a specific `format` when you want field-precision.

**Add a company-internal agent or a new service** — two places:

1. **Route it** so traffic reaches the guard:
   - *Base-URL proxy:* add a route in `aegis.config.json`:
     ```jsonc
     { "matchPrefix": "/v1/chat", "upstream": "https://ai-gateway.acme-internal.com",
       "format": "openai", "mode": "redact" }
     ```
   - *System / transparent proxy:* add the host to `mitm.hosts` (exact, or a `.suffix`):
     ```jsonc
     "mitm": { "hosts": ["ai-gateway.acme-internal.com", "bedrock-runtime.us-east-1.amazonaws.com"] }
     ```
2. **Budget it** (optional) — per-service cap + pricing for its model names:
   ```jsonc
   "budget": {
     "enabled": true, "windowHours": 24, "action": "block",
     "perService": { "ai-gateway.acme-internal.com": { "maxCostUsd": 25 } },
     "pricing": { "acme-llm": { "input": 1, "output": 3 } }
   }
   ```

Budgets are keyed by the **upstream host**, so each service (Azure, Bedrock, your gateway) is
tracked and capped independently. `aegis budget` and the dashboard show per-service spend.

---

## Interception modes

Four ways for traffic to reach the guard — all sharing one offline detection engine.

```mermaid
flowchart TD
    subgraph Modes["How agents reach Aegis"]
        direction TB
        M1["1 - Base-URL proxy<br/>aegis start<br/>sets ANTHROPIC_BASE_URL"]
        M2["2 - System proxy<br/>aegis proxy<br/>HTTPS_PROXY + trusted CA"]
        M3["3 - Transparent<br/>aegis proxy --transparent<br/>iptables / pf REDIRECT"]
        M4["4 - VS Code extension<br/>wraps 1-3 + live in-editor scan"]
    end
    M1 & M2 & M3 & M4 --> Engine["Local detection engine<br/>regex - dictionary - code markers"]
    style Engine fill:#238636,color:#fff
```

| Mode | Agents reached | Setup cost | OS |
|---|---|---|---|
| **Base-URL proxy** | any agent that reads `*_BASE_URL` | trivial | all |
| **System proxy** | anything honoring `HTTPS_PROXY` + the CA | install a root CA once | all |
| **Transparent** | any app, even hardcoded endpoints | iptables/pf rule (root) | Linux + macOS |
| **VS Code extension** | editor + terminals (wraps the above) | install the `.vsix` | all |

---

## Architecture

```mermaid
flowchart TB
    subgraph Client["Client side"]
        AG["AI Agent / curl / app"]
    end

    subgraph AegisProc["Aegis process - localhost"]
        direction TB
        ENTRY{"Entry point"}
        ENTRY --> BUP["Base-URL proxy<br/>server.ts / proxy.ts"]
        ENTRY --> SYS["System proxy MITM<br/>mitm.ts"]
        SYS --- CA["CertAuthority<br/>ca.ts"]
        SYS --- SNI["SNI peek<br/>sni.ts"]

        BUP --> CORE
        SYS --> CORE

        subgraph CORE["Scrub core"]
            direction TB
            MSG["messages.ts<br/>walk request body"]
            SCR["Scrubber<br/>scrub/index.ts"]
            DET["Detectors<br/>secrets - pii - network<br/>dictionary - code"]
            VAULT["Vault<br/>placeholders.ts"]
            MSG --> SCR --> DET
            SCR --> VAULT
        end

        CORE --> FWD["Forwarder<br/>http / https"]
        RESP["Restorer<br/>stream.ts SSE + Vault.restoreDeep"]
        AUDIT["AuditLog<br/>audit.ts"]
    end

    PROV["AI Provider"]

    AG -->|"request"| ENTRY
    FWD -->|"scrubbed"| PROV
    PROV -->|"response"| RESP
    RESP -->|"restored"| AG
    CORE -.-> AUDIT

    style AegisProc fill:#0d1117,color:#fff
    style CORE fill:#161b22,color:#fff
    style PROV fill:#30363d,color:#fff
```

---

## Core engine — UML class diagram

```mermaid
classDiagram
    class Detector {
        <<interface>>
        +string name
        +Category category
        +run(text) RawMatch[]
    }
    class Scrubber {
        -Detector[] detectors
        +detect(text) RawMatch[]
        +scrub(text, vault) ScrubResult
    }
    class Vault {
        -Map~string,string~ forward
        -Map~string,string~ backward
        +placeholderFor(value, type) string
        +restore(text) string
        +restoreDeep(obj) obj
    }
    class SseRestorer {
        -Vault vault
        -string carry
        +feed(chunk) string
        +end() string
    }
    class CertAuthority {
        +string caCertPem
        +string leafKeyPem
        +contextFor(host) SecureContext
        +mintLeaf(host) string
    }
    class AuditLog {
        +record(entry) void
    }
    class RawMatch {
        +int start
        +int end
        +string value
        +string type
        +Category category
        +Severity severity
    }

    Detector <|.. SecretsDetector
    Detector <|.. PiiDetector
    Detector <|.. NetworkDetector
    Detector <|.. DictionaryDetector
    Detector <|.. CodeDetector

    Scrubber o-- "many" Detector : runs
    Scrubber ..> RawMatch : produces
    Scrubber ..> Vault : redacts via
    SseRestorer ..> Vault : restores via
```

> The detectors are pure functions over text. Adding a new category is one file implementing
> the `Detector` interface in [`src/scrub/detectors/`](src/scrub/detectors/).

---

## Request lifecycle (sequence)

The redact, forward, and restore round trip, including streaming responses:

```mermaid
sequenceDiagram
    autonumber
    participant C as Agent (employee)
    participant A as Aegis (local)
    participant V as Vault (in-memory)
    participant P as AI Provider

    C->>A: POST /v1/messages (contains real secret + email + codename)
    A->>A: parse JSON, walk system + messages text
    A->>V: placeholderFor("sk-ant-...","ANTHROPIC_KEY")
    V-->>A: [[REDACTED:ANTHROPIC_KEY:1]]
    Note over A,V: same value maps to same stable placeholder
    A->>P: forward scrubbed request (+ employee's own API key)
    Note over A,P: Provider never sees the real secret
    P-->>A: response stream (may echo placeholders)
    loop each SSE delta
        A->>V: restore placeholders (buffers split tokens)
        V-->>A: real value
        A-->>C: delta with real values
    end
    A-->>A: audit: counts + types only (never values)
```

---

## Redact / restore decision (flowchart)

```mermaid
flowchart TD
    Start(["incoming request body"]) --> J{"Content-Type<br/>JSON?"}
    J -- no --> Fwd["forward unchanged"]
    J -- yes --> Det["run detectors on<br/>system + messages text"]
    Det --> M{"any matches?"}
    M -- none --> Clean["forward as-is<br/>action = clean"]
    M -- yes --> B{"mode = block<br/>OR category in blockOn?"}
    B -- yes --> Block["403 blocked<br/>NOT forwarded<br/>tell user what to remove"]
    B -- no --> Mode{"mode?"}
    Mode -- warn --> Warn["forward ORIGINAL<br/>+ log"]
    Mode -- redact --> Red["replace right to left<br/>with Vault placeholders"]
    Red --> FwdS["forward scrubbed"]
    FwdS --> Resp["restore placeholders<br/>in response"]

    style Block fill:#da3633,color:#fff
    style Red fill:#1f6feb,color:#fff
    style Resp fill:#238636,color:#fff
```

---

## Detection pipeline

Every text field runs through all enabled detectors; overlapping hits are resolved
(earliest, then longest wins) before replacement.

```mermaid
flowchart LR
    T["text"] --> S["secrets"]
    T --> P["pii"]
    T --> N["network"]
    T --> D["dictionary"]
    T --> C["code"]
    S --> O["resolveOverlaps()"]
    P --> O
    N --> O
    D --> O
    C --> O
    O --> R["replace right to left<br/>via Vault.placeholderFor()"]
    R --> Out["scrubbed text"]
```

**Built-in detectors**

| Category | Examples |
|---|---|
| `secret` | AWS / GCP / Anthropic / OpenAI keys, GitHub tokens, Slack/Stripe/SendGrid/Twilio/npm tokens, JWTs, PEM private keys, DB-URI passwords, generic `password=` / `secret=` |
| `pii` | emails, phone numbers, SSNs, Luhn-validated credit cards |
| `network` | IPv4 addresses, internal hostnames (`*.internal`, `*.corp`, `*.svc.cluster.local`) |
| `dictionary` | your codenames, customer names, internal domains (configured) |
| `code` | `CONFIDENTIAL` / `PROPRIETARY` markers, internal package namespaces |
| `identity` | person names, street addresses, DOB, IBAN, passport, **organizations, locations** |
| `entropy` | high-entropy novel tokens regex misses (opt-in; off by default) |
| `ner` (optional) | local Presidio/GLiNER model via `nerCommand` for context-aware PII |

---

## System proxy and transparent interception

### System proxy (CONNECT + locally-trusted CA)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Aegis proxy
    participant CA as Aegis CA
    participant P as Provider

    C->>A: CONNECT api.anthropic.com:443
    A-->>C: 200 Connection Established
    C->>A: TLS ClientHello (SNI = api.anthropic.com)
    alt SNI on allowlist
        A->>CA: mint leaf cert for host
        CA-->>A: cert signed by Aegis root
        A-->>C: TLS handshake AS api.anthropic.com
        C->>A: encrypted request
        A->>A: decrypt in memory, then scrub
        A->>P: re-encrypt + forward (verifies REAL provider cert)
        P-->>A: response
        A-->>C: restored response
    else not on allowlist (bank, email, ...)
        A->>P: blind TCP tunnel - never decrypted
    end
```

### Transparent mode (OS-level redirect)

For apps that ignore `HTTPS_PROXY`, redirect at the packet level and route by SNI:

```mermaid
flowchart TD
    App["Any app opens HTTPS :443"] --> Rule{"iptables / pf<br/>REDIRECT"}
    Rule -->|"excludes proxy's own uid<br/>(no loop)"| TP["Transparent listener :8443"]
    TP --> Peek["peek TLS ClientHello -> SNI<br/>sni.ts - no decryption"]
    Peek --> Allow{"SNI in allowlist?"}
    Allow -- yes --> MITM["TLS-terminate w/ minted cert<br/>then scrub, then forward"]
    Allow -- no --> Blind["blind-tunnel to SNI:443<br/>never decrypted"]
    style MITM fill:#1f6feb,color:#fff
    style Blind fill:#30363d,color:#fff
```

> **Loop avoidance:** the redirect rule excludes the proxy's own uid (`! --uid-owner` on Linux,
> `no rdr ... user` on macOS), so the proxy's *forward* connections are not redirected back into
> itself. Run the proxy as a dedicated user and pass its uid.

---

## Prerequisites

- **Node.js >= 18.17** (`node --version`). Uses the built-in global `fetch` and web streams.
- **npm** (ships with Node).
- For **transparent mode** only: Linux with `iptables`, or macOS with `pfctl` — and `sudo`.
- No API key, account, or network access is needed to run or test Aegis.

---

## Install and build

```bash
git clone <repo-url>
cd B2B
npm install        # installs deps (node-forge for certificates; dev: typescript, vitest, tsx)
npm run build      # compiles TypeScript to dist/
npm test           # runs the 119-test suite (optional but recommended)
```

After `npm run build`, the CLI entry point is `dist/cli.js`. Run it with `node dist/cli.js <command>`.
During development you can skip the build step and run from source with `npx tsx src/cli.ts <command>`.

Show all commands:

```bash
node dist/cli.js help
```

---

## Running Aegis

Pick the mode that matches how broadly you need to cover agents. All modes use the same
detection engine and the same `aegis.config.json`.

### Mode 1 — Base-URL proxy (simplest, recommended to start)

Best for agents that read `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` (Claude Code, OpenAI SDKs, most CLIs).

```bash
# 1. Start the proxy (foreground; Ctrl-C to stop)
node dist/cli.js start
# -> Aegis DLP guard listening on http://127.0.0.1:8787

# 2. In the shell that runs your agent, point it at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1

# 3. Run your agent normally — requests are now scrubbed automatically
claude            # or cursor, or your own script
```

To make every new terminal route through Aegis automatically (writes a clearly-marked,
reversible block to your shell profile):

```bash
node dist/cli.js setup           # enable for all terminals
node dist/cli.js setup --undo    # remove it
```

### Mode 2 — System proxy (covers any HTTPS_PROXY-aware app)

```bash
# 1. One time: generate and trust the root CA (prints OS-specific instructions)
node dist/cli.js ca
#    Node agents can skip the OS install: export NODE_EXTRA_CA_CERTS=~/.aegis/ca.crt

# 2. Start the HTTPS-intercepting proxy (foreground)
node dist/cli.js proxy
# -> Aegis system proxy on http://127.0.0.1:8788

# 3. Route apps through it
export HTTPS_PROXY=http://127.0.0.1:8788
export HTTP_PROXY=http://127.0.0.1:8788
```

Only allowlisted AI hosts are decrypted; all other traffic is blind-tunnelled and never read.

### Mode 3 — Transparent (catches apps that ignore proxy settings; Linux/macOS)

```bash
# 1. Run the proxy (and its transparent listener) as a dedicated user
sudo -u aegis node dist/cli.js proxy --transparent

# 2. Print the redirect rules (review them), or apply directly as root
node dist/cli.js transparent --uid "$(id -u aegis)"            # prints iptables (Linux) / pf (macOS)
sudo node dist/cli.js transparent --apply --uid "$(id -u aegis)"   # Linux: applies them

# Undo later
sudo node dist/cli.js transparent --undo --apply --uid "$(id -u aegis)"
```

### Run in the background (optional)

```bash
node dist/cli.js start > aegis.log 2>&1 &     # start detached, logs to aegis.log
node dist/cli.js status                       # confirm it is up
kill %1                                        # stop it
```

### Verify it is working

```bash
# In another terminal, confirm the guard is live
node dist/cli.js status
curl http://127.0.0.1:8787/__aegis/health      # -> {"status":"ok",...}

# Confirm scrubbing without any AI: scan a file for confidential data
node dist/cli.js scan path/to/file.env
```

---

## Web control panel (GUI)

A local dashboard to operate the guard without the command line. It runs as part of the Aegis
process and is served on localhost only.

**As a desktop app window (recommended):**

```bash
node dist/cli.js app            # opens a standalone, chromeless app window
npm run app                     # same
```

`aegis app` opens the dashboard in a dedicated window using an installed Chromium-family
browser in app mode (no Electron, no extra dependency). It appears in the taskbar like a native
application. If no Chromium browser is found, it falls back to your default browser.

**As a browser tab:**

```bash
node dist/cli.js gui            # http://127.0.0.1:8799
node dist/cli.js gui --open     # also open it in your browser
```

**Inside VS Code:** run **Aegis: Open Dashboard Panel** (a docked panel) or **Aegis: Open
Dashboard** (external browser).

The page provides:

- **Guard controls** — start/stop the base-URL and system proxies with live status indicators.
- **Live redaction tester** — paste any text; see the findings and exactly what the AI would
  receive (scrubbed). Detection runs locally; nothing leaves the machine.
- **Policy and detectors** — switch mode, toggle detector categories, set **per-category
  actions**, edit the **dictionary** and **allowlist**, applied to running proxies immediately.
- **Activity** — a live feed of redaction/block events (counts and types only, never values).

```text
+---------------------------------------------------------------+
|  AEGIS  Confidential Data Guard      [*Base-URL] [ System ]    |
+----------------------------+----------------------------------+
|  Guard controls            |  Policy & detectors              |
|  * Base-URL proxy  [Stop]  |  Action: (redact v)              |
|  o System proxy    [Start] |  [x]secrets [x]pii [x]network    |
+----------------------------+----------------------------------+
|  Live redaction tester                                        |
|  [ paste .env / code / notes ............................. ]  |
|  Scrubbed -> key [[REDACTED:ANTHROPIC_KEY:1]]   Findings (3)  |
+---------------------------------------------------------------+
|  Activity   [REDACT] 19:24:01  /v1/messages  ANTHROPIC_KEY×1  |
+---------------------------------------------------------------+
```

---

## CLI commands

```text
aegis start       Base-URL proxy. Agents set ANTHROPIC_BASE_URL/OPENAI_BASE_URL to it.
aegis proxy       System proxy (HTTPS interception). Add --transparent for OS-level capture.
aegis transparent Print (or --apply as root) the iptables/pf REDIRECT rules.
aegis app         Open the control panel as a standalone desktop app window.
aegis gui         Launch the local web control panel (default :8799, --open to open browser).
aegis status      Check whether the guard is running (probes all ports).
aegis budget      Show token / cost spend against the configured budget.
aegis ca          Show / export the root CA and OS trust instructions.
aegis setup       Auto-route ALL terminals through the base-URL guard ( --undo to revert ).
aegis scan        Scan a file (or stdin) for findings; exits non-zero so it gates CI/pre-commit.
aegis scan-history Scan the entire git history for committed secrets.
aegis report      Compliance report (PCI/HIPAA/GDPR) from the audit log.
aegis optimize    Preview prompt-compression token savings on a file/stdin.
aegis fleet       Run the central fleet collector (aggregate spend across machines).
aegis init        Write a starter aegis.config.json.
```

Common flags: `--config <path>`, `--port <n>`, `--mode redact|block|warn` (start),
`--transparent` (proxy), `--uid <uid> --apply --undo --platform linux|darwin` (transparent),
`--export <path>` (ca), `--undo` (setup).

```mermaid
stateDiagram-v2
    [*] --> Stopped
    Stopped --> Running : aegis start / proxy
    Running --> Stopped : Ctrl-C / aegis stop (extension)
    Running --> Running : request, scrub, forward, restore
    note right of Running
        aegis status shows up
        GET /__aegis/health returns ok
    end note
```

---

## Configuration

`aegis.config.json` (see [`aegis.config.example.json`](aegis.config.example.json)). If absent,
sensible defaults are used. Generate one with `node dist/cli.js init`.

```jsonc
{
  "port": 8787,
  "host": "127.0.0.1",

  "mode": "redact",            // redact | block | warn (global default)
  "blockOn": ["secret"],       // categories that hard-block regardless of mode

  // Policy-as-code: per-category actions (strictest wins for mixed requests)
  "categoryActions": { "secret": "block", "pii": "redact", "network": "warn" },
  // False-positive suppression: literal values or /regex/ strings, never flagged
  "allowlist": ["AKIAIOSFODNN7EXAMPLE", "/@example\\.com$/"],

  "detectors": {
    "secrets": true, "pii": true, "identity": true, "network": true,
    "dictionary": true, "code": true, "entropy": false
  },
  "scanResponses": true,        // also scan AI responses for new secrets
  "encryption": { "enabled": false }, // AES-256-GCM token instead of an index placeholder
  "optimize": { "enabled": false, "aggressive": false }, // compress prompts to cut tokens
  "nerCommand": "",             // optional: a LOCAL NER command for context-aware PII
  "policyFile": "",             // optional: shared team policy merged over local config

  "dictionary": ["Project Phoenix", "acme-internal.com", "BigCustomer Inc"],
  "code": {
    "markers": ["CONFIDENTIAL", "PROPRIETARY", "INTERNAL USE ONLY"],
    "internalNamespaces": ["com.acme.internal", "@acme/internal"]
  },

  "routes": [
    { "matchPrefix": "/v1/messages",         "upstream": "https://api.anthropic.com", "format": "anthropic", "mode": "redact" },
    { "matchPrefix": "/v1/chat/completions", "upstream": "https://api.openai.com",    "format": "openai", "mode": "block" }
  ],

  "mitm": { "port": 8788, "transparentPort": 8443, "hosts": ["api.anthropic.com", "api.openai.com"] },

  // Token / cost spend control across AI services + per employee (off by default)
  "budget": {
    "enabled": true,
    "windowHours": 24,
    "action": "block",            // block (429) or warn when a limit is hit
    "maxTokens": 2000000,         // total tokens per window
    "maxCostUsd": 50,             // total cost per window
    "maxRequestTokens": 200000,   // hard cap on one request
    "perService": { "api.openai.com": { "maxCostUsd": 20 } },

    "identifyHeader": "x-aegis-user", // header that names the employee
    "maxUserTokens": 200000,          // default per-employee token cap
    "maxUserCostUsd": 10,             // default per-employee cost cap
    "perUser": { "alice@acme.com": { "maxCostUsd": 50 } }
  },

  "auditLog": "./aegis-audit.log"
}
```

Environment overrides: `AEGIS_PORT`, `AEGIS_HOST`, `AEGIS_MODE`, `AEGIS_HOME` (CA directory),
`AEGIS_POLICY` (shared policy file).

### Policy-as-code

Actions resolve in layers, and for a request touching several categories the **strictest action
wins** (`block` > `redact` > `warn`):

1. `categoryActions[category]` — per-category override (e.g. `secret: block`, `pii: redact`)
2. the route's own `mode` (per-route override)
3. the global `mode`
4. `blockOn` categories always escalate to `block`

`allowlist` entries (literal values or `/regex/`) are suppressed before any of this, for
false-positive control. A central team can govern all of the above from one shared file via
`policyFile` / `AEGIS_POLICY`, merged authoritatively over local settings.

---

## VS Code extension

The extension ([`extension/`](extension/)) is the developer-facing front-end. It runs the guard
in-process and adds live in-editor protection.

```mermaid
flowchart TB
    subgraph VS["VS Code extension"]
        Act["activate()"]
        Act --> Diag["DiagnosticsManager<br/>live squiggles + Redact quick-fix"]
        Act --> PC["ProxyController<br/>base-URL guard"]
        Act --> SP["SystemProxyController<br/>HTTPS interception + CA"]
        Act --> SB["StatusBar"]
        PC --> Env["environmentVariableCollection<br/>sets *_BASE_URL for terminals"]
        SP --> Env2["sets HTTPS_PROXY + NODE_EXTRA_CA_CERTS"]
    end
    Diag --> Core["dist/scrub (same engine)"]
    PC --> Core
    SP --> Core
    style Core fill:#238636,color:#fff
```

**Build and install:**

```bash
cd extension
npm install
npm run package                                  # produces aegis-guard-0.1.0.vsix
code --install-extension aegis-guard-0.1.0.vsix
```

**Develop (Extension Development Host):** open the repo in VS Code and press `F5` — the launch
config builds and launches the extension.

**Commands:** Start/Stop Guard Proxy, Start/Stop System Proxy, Show CA Trust Instructions,
Protect All Terminals, Scan File / Workspace, Redact Selection, Copy as Redacted, Show Activity Log,
Open Dashboard.

---

## Checking status

```bash
node dist/cli.js status
```

```text
Aegis status

  up    base-URL proxy         127.0.0.1:8787   (mode=redact)
  down  system proxy           127.0.0.1:8788
  down  transparent listener   127.0.0.1:8443

Aegis is running.
```

Exits `0` if anything is up, `1` if nothing is. Other checks:

| Check | Command |
|---|---|
| Health endpoint | `curl http://127.0.0.1:8787/__aegis/health` |
| Port listening | `ss -ltn \| grep -E ':8787\|:8788\|:8443'` |
| Process alive | `pgrep -af "dist/cli.js"` |
| Live activity | `tail -f aegis-audit.log` |

In the extension, the Aegis status-bar item shows `Guard on` / `Guard off`.

---

## Security and privacy

```mermaid
flowchart LR
    Data["your data"] --> Local["local regex/dictionary<br/>src/scrub"]
    Local -->|"NO network, NO AI, NO key"| Decide["redact / block / warn"]
    Decide --> Scrubbed["scrubbed request"] --> Provider["provider"]
    Real["real values"] -.->|"never crosses"| Provider
    style Real fill:#da3633,color:#fff
    style Local fill:#238636,color:#fff
```

- **No API key, no AI calls for detection.** The engine in [`src/scrub/`](src/scrub/) is pure
  local matching. Sending data to an AI to check it would defeat the purpose; Aegis never does.
- **Your agent's key is only forwarded** — never read, stored, or logged.
- **Ephemeral vault.** The redact/restore mapping lives in memory for a single request, then is
  discarded. Real values are never written to disk.
- **Audit log records counts and types only**, safe to ship to a SIEM.
- **Encryption mode (optional).** With `encryption.enabled`, each confidential value is
  **AES-256-GCM-encrypted** with a local key and sent to the AI as `[[AEGIS:<ciphertext>]]`; the
  response is decrypted back. The key lives only at `~/.aegis/redaction.key` (`0600`) and is never
  sent anywhere. Restoration is **stateless** (survives restarts / works across instances with the
  same key), and GCM auth means a model-mangled token fails closed instead of producing garbage.
  Trade-off: ciphertext tokens are longer than index placeholders, so they cost more prompt tokens
  — the default index-placeholder mode is lighter for everyday use.
- **MITM decrypts only allowlisted AI hosts**; everything else is blind-tunnelled. The root CA's
  private key never leaves the machine.
- **Only runtime dependency:** `node-forge` (X.509 certificates). No AI SDK.

---

## Project structure

```
src/
  cli.ts            commands: start, proxy, transparent, status, ca, setup, scan, init
  config.ts         config loader + DEFAULT_CONFIG + central policy merge
  policy.ts         policy-as-code decisions (per-category / per-route actions)
  budget.ts         token / cost spend control (rolling-window BudgetTracker)
  crypto.ts         AES-256-GCM encryption mode (local key, encrypt/decrypt tokens)
  optimize.ts       local prompt compression (loop reduction passes to convergence)
  auth.ts           RBAC + token/JWT (SSO) verification for the control plane
  fleet.ts          fleet collector + aggregator + agent reporting
  mcp.ts            MCP JSON-RPC detection + tool deny-list
scripts/ner_presidio.py  ready-to-use local NER for the nerCommand hook
  types.ts          shared types
  server.ts         base-URL proxy bootstrap
  proxy.ts          base-URL request handling (scrub, forward, restore) + /__aegis/health
  messages.ts       Anthropic/OpenAI body walkers
  stream.ts         SSE streaming restorer (handles split placeholders)
  audit.ts          append-only audit (counts only)
  status.ts         liveness probes for `aegis status`
  gui.ts            local control-panel server (control API + SSE)
  gui-page.ts       the dashboard HTML/CSS/JS (iOS-style, inlined)
  app.ts            launches the dashboard as a desktop app window
  history.ts        git-history secret scanning
  report.ts         compliance reporting (PCI/HIPAA/GDPR)
  mitm.ts           system proxy: CONNECT + transparent listener (SNI-routed)
  ca.ts             CertAuthority: root CA + per-host leaf certs
  sni.ts            TLS ClientHello SNI extractor
  transparent.ts    iptables (Linux) / pf (macOS) rule generation
  scrub/
    index.ts        Scrubber, resolveOverlaps, summarize
    placeholders.ts Vault (ephemeral redact/restore map)
    detectors/      secrets, pii, identity, ner, network, dictionary, code, util
extension/          VS Code extension (wraps the engine)
test/               119 tests: detectors, identity, entropy, roundtrip, stream, crypto, optimize,
                    policy, budget, providers, ca, mitm, sni, report, history, samples, enterprise
```

---

## Testing

```bash
npm test          # 119 unit tests across 18 suites
npm run test:watch
```

```mermaid
flowchart LR
    subgraph Suite["119 unit tests · 18 suites"]
        D["detectors<br/>secrets/pii/dictionary/code"]
        ID["identity<br/>names/address/DOB/IBAN"]
        EN["entropy<br/>novel high-entropy tokens"]
        R["roundtrip<br/>redact then restore + body walkers"]
        S["stream<br/>split-placeholder SSE restore"]
        CR["crypto<br/>AES-256-GCM encrypt/decrypt + key"]
        OP["optimize<br/>compression convergence"]
        PO["policy<br/>per-category/route + allowlist"]
        BU["budget<br/>token/cost + per-employee caps"]
        PR["providers<br/>Azure/Gemini/Bedrock usage + format"]
        CA["ca<br/>leaf validates vs root (real TLS)"]
        M["mitm<br/>scrub/restore + blind-tunnel + transparent SNI"]
        SN["sni<br/>ClientHello parse + iptables/pf rules"]
        RP["report<br/>PCI/HIPAA/GDPR mapping"]
        HI["history<br/>git-history secret scan"]
        SA["samples<br/>real fixture files"]
        EN2["enterprise<br/>RBAC/JWT + fleet + MCP + orgs/locations"]
    end
```

### Live end-to-end harness

Beyond the unit tests, a live harness starts real Aegis proxies in front of a fake AI upstream
and drives them over HTTP, asserting the whole pipeline (**21 checks across 9 scenarios**):

| Scenario | Verified |
|---|---|
| Redact + restore | upstream gets placeholders only; client reply restores the real value |
| Clean passthrough | original text forwarded, `200` |
| Policy block | secret → `403`, never forwarded |
| Optimization | blank lines/extra spacing removed before sending |
| Per-employee budget | over-cap employee → `429`; others unaffected |
| Encryption mode | upstream gets `[[AEGIS:…]]` ciphertext; client reply decrypted |
| Response scanning | a secret in the AI's output is flagged (`direction: response`) |
| Multi-provider (Gemini) | `contents[].parts[].text` scrubbed |
| Health endpoint | `{"status":"ok"}` |

Verified end-to-end: the provider receives only placeholders/ciphertext; the client gets real
values restored (even across split stream chunks); minted leaf certs validate against the root
over real TLS; non-AI hosts are never decrypted.

---

## Roadmap

- Local NER model for unstructured PII (names, addresses), still fully offline.
- Per-route and per-category action overrides.
- Entropy-based detector for novel, un-templated secrets.
- Windows WFP transparent redirection (Linux + macOS already supported).
- Admin dashboard over the audit log.

---

Built as a defense-in-depth guard. Pattern-based detection catches the overwhelming majority of
structured secrets and configured terms, but is not a substitute for keeping real production
secrets off developer machines.
