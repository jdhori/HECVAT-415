# HECVAT 4.1.5 — Web Form

**Higher Education Community Vendor Assessment Toolkit**
*Solution Provider Response Tool — EDUCAUSE © 2025*

---

## Contents of this ZIP

```
HECVAT-415/
├── HECVAT-415.html   — Open this file in your browser to use the form
├── hecvat-data.js    — Question data (332 questions from HECVAT 4.1.5 xlsx)
├── hecvat-app.js     — Application logic
└── hecvat.css        — Stylesheet
```

All four files must stay in the **same folder**. The HTML file references the
other three by relative path, so moving them apart will break the tool.

---

## Getting Started

1. **Unzip** the archive into a folder on your computer.
2. **Open `HECVAT-415.html`** in a modern browser — Chrome, Firefox, Edge, or
   Safari. No internet connection, server, or installation required.
3. Begin on the **Start Here** section. Your answers to the Required Questions
   there determine which other sections apply to your product.

> **Tip:** Complete Start Here first. The routing questions (REQU-01 through
> REQU-08) control which sections are shown as required. Sections that don't
> apply to your product are automatically marked **N/R** (Not Required) in the
> sidebar.

---

## The Form at a Glance

### Sections

| # | Section | Questions | Critical |
|---|---------|-----------|---------|
| 1 | Start Here | 22 | 1 |
| 2 | Organization | 51 | 12 |
| 3 | Product | 46 | 19 |
| 4 | Infrastructure | 56 | 17 |
| 5 | IT Accessibility | 23 | 4 |
| 6 | Case-Specific | 68 | 11 |
| 7 | AI | 37 | 16 |
| 8 | Privacy | 189 | 44 |

**332 total questions** — 90 Critical, 139 Standard, 72 Minor importance, 31 unscored routing/info questions.

### Scoring

Each scored question carries a point value based on its importance level:

| Importance | Points |
|------------|--------|
| Critical   | 20 pts |
| Standard   | 10 pts |
| Minor      | 5 pts  |

Answering **N/A** excludes that question from your total — it reduces both
earned and possible points proportionally, so it doesn't penalise your score.

The **score banner** at the top of the page updates in real time, showing:
- Points earned / points possible
- Percentage score (colour-coded: green ≥ 80%, amber ≥ 60%, red below)
- Count of compliant and non-compliant responses
- Count of unanswered critical issues

---

## Answering Questions

### Yes / No / N/A buttons

Most questions use a three-button toggle. Click the appropriate answer. After
you answer, a **compliance indicator** appears below the buttons showing
whether your answer matches the expected compliant response for that question.

- **✓ Compliant response** — your answer matches the expected response
- **✗ Non-compliant response** — your answer differs from expected
- **— N/A — Not applicable** — excluded from scoring

When you tab into a button group using the keyboard, a **tooltip** appears
above the buttons showing the full question text — useful for keyboard-only
navigation.

### Text and textarea fields

Some questions ask for free-text responses (contact names, descriptions,
architecture summaries, etc.). Type directly into the field. These answers are
not scored but form part of the submitted assessment record.

### Conditional guidance

Many questions show additional guidance when you answer. A green banner
appears after answering **Yes**, or a red banner after answering **No**, with
specific instructions on what to provide or which related section to complete.

### Adding notes

Every question has an **+ Add notes** button. Click it to open a notes field
where you can add context, qualifications, caveats, or references. Notes are
included in all exports.

---

## Cross-Referenced Questions

132 of the 332 questions appear in more than one section (for example, general
company information applies to every section; HIPAA questions appear in both
Case-Specific and Privacy).

**Each question is only answered once** — in the first section where it
appears. In later sections, you'll see a compact reference row showing your
current answer and a link to jump back to where the question is answered. When
you update an answer, all cross-references update immediately.

---

## Conditional Section Routing

Answering **No** to a routing question in Start Here automatically marks
certain sections as not required:

| Routing Question | Affects Section(s) |
|------------------|--------------------|
| REQU-01 — Are you offering a product or platform? | Product, Infrastructure |
| REQU-02 — Does your product or service have an interface? | IT Accessibility |
| REQU-04 — Does your solution have AI features? | AI |
| REQU-08 — Does your solution have access to personal or institutional data? | Privacy |

When a section is not required:
- Its sidebar nav button is dimmed and labelled **N/R**
- An amber banner appears inside the section explaining why
- The section's questions remain visible for reference but are excluded from
  required completion

You can still navigate to and answer questions in a gated section if they are
relevant — the gating is advisory, not a lock.

---

## Saving and Loading Progress

### Save Progress

Click **Save Progress** in the left sidebar. Your responses are encrypted
using **AES-256-GCM** (Web Crypto API) before being written to your browser's
`localStorage`. The encryption key is stored only in `sessionStorage`
(tab-scoped), meaning:

- The stored data is ciphertext — unreadable without the session key
- Closing the tab discards the session key; you will not be able to reload
  that specific save in a new tab or session

> **Important:** Because the session key is tab-scoped, always **Export JSON**
> before closing your browser if you want to resume later. The JSON export
> contains your plaintext responses and can be re-imported in a future session
> (manual re-entry required — JSON is for archiving, not automatic re-import).

### Load Progress

Click **Load Progress** to decrypt and restore a previously saved session from
the current tab's `localStorage`. Every loaded record is validated before
being applied — records that don't match the expected structure are discarded
and counted in a status message.

**Note:** Saves created by older unencrypted versions of this tool are
rejected on load as a security measure. Use **Clear & Reset** and start fresh
if you encounter this message.

### Clear & Reset

Click **Clear & Reset** to wipe all saved data from `localStorage` and
`sessionStorage` and reload the form. A confirmation dialog appears before
anything is deleted. Use this when you have finished and exported your
responses and want to ensure no assessment data remains in the browser.

---

## Exporting Responses

### Export JSON

Exports a structured `.json` file containing:

```json
{
  "meta": {
    "tool": "HECVAT",
    "version": "4.1.5",
    "exported": "2025-04-07T12:00:00.000Z",
    "notice": "This file contains sensitive assessment data..."
  },
  "score": {
    "earned": 840,
    "pot": 1200,
    "pct": 70,
    "comp": 84,
    "nc": 12,
    "ci": 3
  },
  "responses": {
    "GNRL-01": {
      "question": "Solution Provider Name",
      "value": "Acme Corp",
      "notes": "",
      "importance": "",
      "primarySection": "start"
    }
  }
}
```

Use JSON for archiving, audit trails, or sharing with your information
security team.

### Export CSV

Exports a `.csv` file with one row per question, including ID, question text,
section, importance, response, notes, expected compliant response, and score
mapping. Suitable for importing into spreadsheet tools.

> **Formula injection protection:** Any cell value beginning with `= + - @`
> is automatically prefixed with a single quote so spreadsheet applications
> treat it as plain text rather than a formula.

### Print

Opens the browser print dialog. The sidebar, score banner, and navigation
controls are hidden in print view, and all sections are expanded for a clean
multi-page output.

> **Security reminder:** Exported files are **plaintext**. Treat them as
> confidential documents — store them securely, transmit only over encrypted
> channels (e.g. TLS/HTTPS), and delete them when no longer needed.

---

## Accessibility

This form was built to meet WCAG 2.1 AA. Key features:

- **Skip to main content** link at the top of every page
- Every interactive element has a unique, descriptive `aria-label` that
  includes the associated question text — screen readers announce the full
  context of each button
- Yes/No/N/A button groups use `role="group"` with `aria-labelledby` pointing
  to the question text element
- A **visual tooltip** appears above button groups when they receive keyboard
  focus, showing the question text for sighted keyboard users
- Compliance status indicators use `aria-live="polite"` for screen reader
  announcement
- The running score banner uses `role="status"` and `aria-live="polite"`
- All cross-reference "Not yet answered" indicators use `aria-live="polite"`
- Section panels use `role="region"` with `aria-labelledby`
- Sidebar navigation supports **Arrow Up / Arrow Down** key navigation between
  sections
- Critical questions are marked with a ★ badge and a distinct left border
- Colour is never the sole means of conveying information — compliance
  indicators also use text labels (✓ / ✗ / —)

---

## Security Architecture

| Control | Implementation |
|---------|---------------|
| localStorage encryption | AES-256-GCM via Web Crypto API |
| Encryption key storage | sessionStorage only (tab-scoped, not persisted) |
| Plaintext fallback | None — save is rejected if Web Crypto unavailable |
| Input validation on load | Shape, type, length, and tag-injection checks on every record |
| DOM XSS prevention | All user content written via `textContent`/`.value`; no `innerHTML` with user data |
| CSV formula injection | OWASP prefix mitigation (`'`) on cells starting with `= + - @ \t \r` |
| Attribute injection | `attr()` helper blocks `on*` event-handler attributes and `javascript:` URLs |
| Content Security Policy | `default-src 'self'` · `script-src 'self'` · `style-src 'self'` · `object-src 'none'` · `base-uri 'self'` · `form-action 'none'` · `frame-ancestors 'none'` |
| No external dependencies | Zero network requests — no CDN scripts, no remote fonts, no analytics |

### Deployment note

The CSP is delivered as a `<meta http-equiv>` tag, which is functional but
lower-assurance than an HTTP response header. If you host this tool on a web
server, add the same policy as an HTTP `Content-Security-Policy` header for
stronger enforcement. The tool is designed to run as a local file (`file://`)
or from a dedicated isolated origin — do not serve it from a shared domain
where other applications also run.

---

## Browser Compatibility

| Browser | Minimum version |
|---------|----------------|
| Chrome / Edge | 88+ |
| Firefox | 84+ |
| Safari | 15+ |

The Web Crypto API (`window.crypto.subtle`) is required for Save Progress. All
modern browsers listed above support it. If you are in a restricted environment
where Web Crypto is unavailable, use **Export JSON** to preserve your responses
instead — saving to localStorage will be blocked.

---

## About HECVAT

The Higher Education Community Vendor Assessment Toolkit (HECVAT) is developed
and maintained by **EDUCAUSE**. It is the higher education community standard
for assessing the information security and privacy practices of third-party
vendors and cloud service providers.

- HECVAT documentation and tutorials: [educause.edu/HECVAT](https://educause.edu/HECVAT)
- HECVAT Users Community Group: [educause.edu community](https://educause.edu)

This web form is an **unofficial implementation** of the HECVAT 4.1.5
questionnaire for digital-first completion. It is not affiliated with or
endorsed by EDUCAUSE. Always refer to the official HECVAT documentation for
authoritative guidance on question interpretation and submission requirements.

---

*HECVAT™ is a trademark of EDUCAUSE. Copyright © 2025 EDUCAUSE.*

---

## Hosted Deployment Guide

This tool is designed to run as a local file (`file://`) but can be hosted on a web server. When hosted, you **must** serve the security headers as HTTP response headers — the `<meta>` tags in `HECVAT-415.html` are a fallback, but HTTP headers provide stronger and more reliable enforcement.

### Server configuration files

The `server-configs/` folder contains ready-to-use configuration snippets:

| File | Platform |
|------|----------|
| `nginx.conf` | nginx 1.18+ |
| `apache.conf` | Apache 2.4+ with mod_headers |
| `_headers` | Netlify and Cloudflare Pages (place at site root) |
| `Caddyfile` | Caddy 2.x (automatic HTTPS) |

### Required HTTP headers

Every server configuration sets these headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';` | Prevents XSS, clickjacking, and injection |
| `X-Frame-Options` | `DENY` | Clickjacking defence (complements CSP `frame-ancestors`) |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type confusion attacks |
| `Referrer-Policy` | `no-referrer` | Prevents URLs containing response data from leaking to third parties |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disables browser APIs the tool does not use |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Forces HTTPS (enable once TLS is confirmed working) |

> **Note:** `X-Frame-Options` and `Strict-Transport-Security` cannot be delivered via `<meta>` tags. They must be HTTP headers. The tool's `<meta>` CSP tag is a belt-and-suspenders measure — it does not replace the HTTP header.

### Deployment on Netlify or Cloudflare Pages

1. Copy the four tool files (`HECVAT-415.html`, `hecvat-app.js`, `hecvat-data.js`, `hecvat.css`) and the `_headers` file into your repository root.
2. Set your publish directory to the repository root.
3. Deploy. Both platforms automatically apply the `_headers` file.

No build step is required — this is entirely static HTML/JS/CSS.

### Access control

HECVAT responses contain sensitive vendor information. Strongly consider:

- **Authentication** — place the tool behind SSO, HTTP Basic Auth, or IP allowlisting rather than exposing it publicly
- **HTTPS only** — do not serve over plain HTTP; the session storage encryption key is transmitted in-browser but the page itself should not be served insecurely
- **Separate origin** — host the tool on its own subdomain (e.g. `hecvat.yourdomain.edu`) rather than sharing an origin with other applications, so the `form-action 'none'` and CSP restrictions are fully isolated

### What the built-in security model covers

| Threat | Mitigation |
|--------|-----------|
| DOM XSS | All user content rendered via `textContent`/`.value`; no `innerHTML` with user data; `sanitize()` as secondary defence |
| Attribute injection | `attr()` helper uses a strict allowlist of ~40 permitted attributes; `data-*` names validated by regex |
| Stored XSS via import | Every imported record runs through `validateRecord()` which checks type, length, and rejects executable HTML tag patterns |
| CSV formula injection | Export prefixes cells starting with `= + - @ \t \r` with a single quote |
| Clickjacking | `frame-ancestors 'none'` in CSP + `X-Frame-Options: DENY` |
| MIME confusion | `X-Content-Type-Options: nosniff` |
| Local storage eavesdropping | AES-256-GCM encryption; session key kept in `sessionStorage` only (tab-scoped, not persisted) |
| Plaintext fallback | Removed — save fails hard if Web Crypto is unavailable |

**What it does not cover:** The AES-256-GCM local storage encryption protects against casual disk/profile inspection (local-at-rest protection). It does not protect against active same-origin XSS — if the page were compromised by script injection, both ciphertext and session key would be accessible from the same context. The primary XSS mitigations are the CSP, DOM-API-only rendering, and the `attr()` allowlist.

---

## Acknowledgments

This tool was developed with assistance from multiple AI coding assistants:

- **Claude Max** (Anthropic)
- **OpenAI Codex** (OpenAI)
- **Gemini** (Google)

AI contributions are also recorded as `Co-Authored-By:` trailers on the initial commit.

