# HECVAT 4.1.6 — Web Form

**Higher Education Community Vendor Assessment Toolkit**
*Solution Provider Response Tool — EDUCAUSE © 2025*

---

## Contents of this ZIP

```
HECVAT-416/
├── index.html         — Open this file in your browser to use the form
├── hecvat-data.js     — Question data (332 questions from HECVAT 4.1.6 xlsx)
├── hecvat-app.js      — Application logic
├── hecvat.css         — Stylesheet
├── hecvat-worker.js   — Web Worker for isolated XLSX import parsing
├── xlsx.mini.min.js   — SheetJS library (loaded by the worker)
├── fflate.min.js      — Local zip read/write (used by the XLSX export)
├── hecvat-template.js — Base64 of the official HECVAT 4.1.6 workbook, loaded
│                        on demand to power the vendor Excel export
└── HECVAT416.xlsx     — Source workbook, kept only to regenerate the template
                         (not loaded at runtime)
```

The runtime files must stay in the **same folder**. The HTML file references
the others by relative path, and `hecvat-worker.js` loads `xlsx.mini.min.js`
via `importScripts`, so moving any of them apart will break the tool.
`hecvat-template.js` is loaded lazily the first time you export to Excel, so
page load stays light. `HECVAT416.xlsx` is kept in the repo only as the source
for regenerating `hecvat-template.js`; it is never fetched by the running tool.

---

## Getting Started

1. **Unzip** the archive into a folder on your computer.
2. **Open `index.html`** in a modern browser — Chrome, Firefox, Edge, or
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

Legacy saved responses that contain an `"N/A"` value (exported before the
N/A button was removed) are still read correctly: on load, N/A values are
treated the way they always were — the question is excluded from the total
by reducing both earned and possible points proportionally, so they don't
penalise your score. The UI itself now offers only Yes and No; leaving a
question **unanswered** is the right way to signal "not applicable" in new
assessments.

The **score banner** at the top of the page updates in real time, showing:
- Points earned / points possible
- Percentage score (colour-coded: green ≥ 80%, amber ≥ 60%, red below)
- Count of compliant and non-compliant responses
- Count of unanswered critical issues

---

## Answering Questions

### Yes / No buttons

Most questions use a two-button toggle. Both buttons start in an **amber
"pending"** state — amber fill, amber border, dark-amber text — so they read
as "awaiting your answer" without implying a preferred choice. Click one to
commit:

- Selecting **Yes** swaps the button to a solid **green** fill with white text
  and a corner ✓ pip.
- Selecting **No** swaps the button to a solid **red** fill with white text
  and a corner ✓ pip.
- Clicking the already-selected button again clears the answer and returns
  both buttons to the amber pending state.

After you answer, a **compliance indicator** appears below the buttons showing
whether your answer matches the expected compliant response. The indicator
uses the **same green or red** as the selected button so the visual thread
from "what I chose" to "what that means" is continuous:

- **✓ Compliant response** — solid green banner; your answer matches the
  expected compliant response for that question
- **✗ Non-compliant response** — solid red banner; your answer differs from
  the expected compliant response

Routing/informational questions (REQU-\*, GNRL-\*, PDOC-01, PDOC-02, etc.)
have no "correct" answer and therefore do not display a compliance banner —
they shape section gating and metadata only.

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

## Multi-Section Questions (GNRL, REQU)

A small number of questions appear in more than one section — general company
information (`GNRL-01` through `GNRL-08`) surfaces in every section, and the
routing questions (`REQU-01` through `REQU-07`) surface in the sections they
gate.

**Each instance is independently answerable.** Every section gets its own
input field plus a **"Sync *\<question-id\>* with other sections"** checkbox
(checked by default, with a unique per-question accessible label such as
`"Sync GNRL-01 with other sections"`).

- **Checkbox checked (linked, default)** — the instance shares the master
  answer with every other instance of the same question. Typing or clicking
  in one place propagates to all linked copies in real time.
- **Checkbox unchecked (independent)** — the instance stores its own
  per-section override. Changes there do not affect other sections, and
  changes elsewhere do not affect this instance. The row gets an amber left
  border so you can see at a glance which instances have drifted.
- **Re-checking** adopts the current master value and discards the local
  override.

Scoring always uses the primary-section answer for each question, so
per-section overrides are a documentation convenience — they don't
double-count.

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

## Analyst Evaluations

Below the **Vendor Response** sidebar group is a second nav group,
**Analyst Evaluations**, with three tabs for reviewers working through a
completed submission:

| Tab | Purpose |
|---|---|
| **Institution Evaluation** | Full analyst review — every scored category with vendor responses, importance overrides, compliance overrides, analyst notes, and a Non-Negotiable flag. |
| **High-Risk Evaluation** | Condensed view: the 90 Critical questions plus any the analyst has flagged as Non-Negotiable. Read-only summary that reflects overrides made elsewhere. |
| **Privacy Analyst Evaluation** | The ten privacy categories (PRGN, PCOM, PDOC, PTHP, PCHG, PDAT, PRPO, INTL, DRPV, DPAI) with the same override controls as Institution Evaluation. |

**Persistence:** Every Importance Override, Compliance Override,
Non-Negotiable flag, and Analyst Notes field is saved with **Save
Progress** (encrypted together with vendor responses), included in the
**JSON** export (as a separate `analystEvaluations` map), and added as four
extra columns on the **CSV** export (`Importance Override`,
`Compliance Override`, `Non-Negotiable`, `Analyst Notes`). Re-importing JSON
or CSV restores every override to its original state, so analyst reviews can
be handed off between reviewers or archived alongside the vendor submission.

Analyst evaluations are **deliberately excluded from the Excel export**, which
is a vendor-facing deliverable (see *Export Excel (for vendors)* below). Keep
analyst overrides in the JSON/CSV exports, which are the evaluator-facing
formats.

### Radar Graphs — Vendor vs Evaluator Scores, and High-Risk Coverage

All three analyst tabs carry a collapsible **📡 Radar Graph** panel directly
under the scorecard, rendered as native SVG inside the tool's CSP.

| Tab | Spokes | Dashed outline (square markers) | Solid outline (round markers) |
|---|---|---|---|
| Institution Evaluation | COMP → ITAC plus the AI and Privacy aggregates | Vendor self-reported score % | Evaluator-adjusted score % |
| Privacy Analyst Evaluation | The ten privacy categories | Vendor self-reported score % | Evaluator-adjusted score % |
| High-Risk Evaluation | Same sections as Institution Evaluation | Score % on that section's **Critical Importance** questions | Score % on the questions flagged **Non-Negotiable** |

Scoring follows the workbook: Critical = 20 pts, Standard = 10, Minor = 5; a
question earns its points only when the answer matches the expected compliant
answer (some privacy questions expect **No**); N/A removes a question from the
total; a blank answer stays in the total and earns nothing. A spoke shows a
hollow marker at the hub when a section has no scorable data, so a real 0 %
never looks like a missing score.

**Failed non-negotiables are flagged on every radar.** Any section containing
a Non-Negotiable question that is non-compliant gets a thick red spoke, a red
`!` badge at the rim, a red label, and a sentence in the graph's screen-reader
description. The data table lists the failing question IDs.

When overrides carry evaluator initials, a row of chips restricts the
evaluator outline (and the non-negotiable flags) to one reviewer, so a lead
analyst can compare how each evaluator graded. **View data as table** lists,
per section: questions, answered / N/A / blank counts, each series' score, the
difference, override count, analyst-note count, vendor-note count, and
non-negotiables flagged and failed.

**Group import for leadership.** **Import JSON** accepts several files at
once. Each evaluator exports their own JSON; a lead picks all of them in one
go and the tool merges them, keeping per-field authorship and logging
conflicts, so the radar chips and the go/no-go report show every reviewer.

**Radar data in exports.** The JSON export carries a `radar` block (every tab,
for all evaluators combined and for each evaluator) and the CSV export ends
with `# Radar` rows holding the same figures. Both are informational: the
importer ignores them and recomputes from the merged answers and overrides.

**Vendor explanations on the chart.** A section whose vendor added notes to
at least one question gets a small solid dot inside its dashed marker, so a
low score backed by written justification reads differently from a bare one.
The data table's **Vendor notes** column gives the count per section.

### Failed non-negotiables — vendor justification vs evaluator notes

Under the High-Risk radar sits a drill-down listing every Non-Negotiable
question that is currently non-compliant. Each entry shows the question, the
initials of whoever flagged it, and two columns side by side:

| Column | Contents |
|---|---|
| Vendor | The answer given, the answer the workbook expects, and the vendor's own note explaining it (or a note that no explanation was given) |
| Evaluator | The analyst note, the initials of who wrote it, and any Compliance Override applied |

This puts the vendor's justification in front of the reviewer at the moment
of judgement rather than three clicks away. The list follows the radar's
evaluator chips, so filtering to one reviewer shows only their flags.

### Appendix — Vendor notes by section

Every evaluation tab ends with a collapsible **Appendix — Vendor notes by
section**, listing each question the vendor annotated, grouped by report
section, with the question ID, the answer given, the question text, and the
full note. The badge on the toggle counts the notes in scope for that tab.

The appendix is collapsed on screen and **always expanded when printing**,
starting on a fresh page, so a printed or PDF-exported evaluation carries the
vendor's own words as a reference section at the back.

### Compliance Plots

Inside **Institution Evaluation** is a collapsible
**📈 Compliance Plots — By Category (95% CI)** panel containing three
complementary charts rendered as native SVG (no external libraries, no
network requests, fully inside the tool's CSP):

1. **Compliance proportion by category with 95% confidence intervals.** One
   bar per category; bar height is the Yes/No compliance rate; whiskers are
   the **Wilson-score 95% CI**. Non-overlapping intervals imply the
   categories differ significantly at p < 0.05.
2. **Answer composition by category.** Stacked bars showing counts of
   Compliant / Non-Compliant / N/A / Unanswered per category so the sample
   size behind each rate is immediately visible. Each segment uses a
   distinct **fill pattern** as well as a distinct color (solid green for
   Compliant, diagonal red stripes for Non-Compliant, amber dots for N/A,
   grey crosshatch for Unanswered) so the chart stays readable without
   relying on color alone.
3. **Pairwise category comparisons (two-proportion z-test).** Heat-map grid
   of every category pair, colored and patterned by **Bonferroni-adjusted**
   significance: `ns` solid grey, `*` amber-with-dots (p<0.05), `**`
   orange-with-stripes (p<0.01), `***` red-with-dense-crosshatch (p<0.001).
   Hover a cell for exact z-statistic, raw p-value, and adjusted p-value.

Every plot is accessible:

- Each chart is a `<figure>` with a `<figcaption>` and the SVG's first two
  children are `<title>` + `<desc>` that narrate every data point in prose
  (e.g. *"APPL: 67% compliant, 95% CI 45% to 84%, n equals 12. ..."*). That
  text is what screen readers actually announce for `role="img"`.
- Every individual bar, stack segment, and heatmap cell carries its own
  nested `<title>` so keyboard/screen-reader users navigating by element hear
  the exact numbers for that element.
- Each figure has a **"View data as table"** toggle that reveals a semantic
  `<table>` with `<caption>`, row/column scope, the Wilson CI, the Standard
  Error of the Mean, and the z-test outputs — the definitive accessible
  alternative when the SVG summary isn't enough.
- Each figure has a **zoom toolbar** (**−** / live **%** readout with
  `aria-live="polite"` / **+** / **Reset**) that scales the SVG from 50% to
  300% in 25% steps while keeping it crisp. The SVG host itself is
  keyboard-focusable and scrolls when zoomed so you can pan.

Plots render lazily — they only build when you open the panel — and
auto-refresh whenever the institution scorecard updates, so they stay in
sync with vendor answers and analyst overrides.

---

## Snapshots

### Take Snapshot

A **snapshot** is a safety net for the browser tab you are working in.
It brings your work back after an accidental reload, a crash, or navigating
away. It is deliberately **not** called a save, because it does not outlive the
browser. **Export JSON** is the copy you keep.

Click **Take Snapshot** in the left sidebar. Your responses **and any
analyst overrides** (Importance Override, Compliance Override,
Non-Negotiable flag, Analyst Notes set in the Institution Evaluation /
Privacy Analyst Evaluation tabs) are encrypted together using
**AES-256-GCM** (Web Crypto API) before being written to your browser's
`localStorage`. The encryption key is stored only in `sessionStorage`
(tab-scoped), meaning:

- The stored data is ciphertext — unreadable without the session key
- Closing the tab discards the session key; you will not be able to reload
  that specific snapshot in a new tab or session
- Legacy snapshots that predate the analyst-evaluation bundle still load; the
  analyst overrides start empty and can be added fresh

> **Important:** Because the session key is tab-scoped, always **Export JSON**
> before closing your browser if you want to resume later. The JSON export
> contains your plaintext responses and can be re-imported in a future session
> (manual re-entry required — JSON is for archiving, not automatic re-import).

The tool now says this in the interface rather than leaving it to the manual.
The first snapshot of each browser session raises a prominent banner explaining
that it cannot be opened once the browser closes, and every later snapshot
repeats a one-line reminder. If you try to **Restore Snapshot** against a
snapshot from an earlier session, the banner explains plainly that the key is gone
by design, that the copy cannot be recovered by anyone, and that **Import
JSON** is the way back. Both banners use `role="alert"`, so screen readers
interrupt with them instead of queuing them behind other messages, and neither
disappears on a timer.

### Restore Snapshot

Click **Restore Snapshot** to decrypt and restore the snapshot taken earlier in
this tab.

You rarely need to click it: when the page loads and a usable snapshot is
waiting, the tool says so and offers a **Restore snapshot** button. If the
snapshot was taken in an earlier browser session it explains that instead, so a
blank form is never left unexplained. Every loaded record is validated before
being applied — records that don't match the expected structure are discarded
and counted in a status message.

**Note:** Snapshots created by older unencrypted versions of this tool are
rejected on load as a security measure. Use **Clear & Reset** and start fresh
if you encounter this message.

### Clear & Reset

Click **Clear & Reset** to wipe all saved data from `localStorage` and
`sessionStorage` and reload the form. A confirmation dialog appears before
anything is deleted. Use this when you have finished and exported your
responses and want to ensure no assessment data remains in the browser.

---

## Exporting Responses

The export formats are split by audience:

- **Excel (`.xlsx`) is for vendors.** It produces a fully working copy of the
  official EDUCAUSE HECVAT 4.1.6 workbook with your answers filled in — the one
  a vendor shares with the institutions assessing them.
- **JSON and CSV are for evaluators.** They round-trip both vendor responses
  and analyst overrides, carry the evaluator's initials, and can be merged
  between reviewers.

### Export JSON

Exports a structured `.json` file containing:

```json
{
  "meta": {
    "tool": "HECVAT",
    "version": "4.1.6",
    "exported": "2025-04-07T12:00:00.000Z",
    "notice": "This file contains sensitive assessment data..."
  },
  "score": { "earned": 840, "pot": 1200, "pct": 70, "comp": 84, "nc": 12, "ci": 3 },
  "responses": {
    "GNRL-01": {
      "question": "Solution Provider Name",
      "value": "Acme Corp",
      "notes": "",
      "importance": "",
      "primarySection": "start"
    }
  },
  "analystEvaluations": {
    "AAAI-01": {
      "question": "Are all systems...",
      "impOverride": "Critical Importance",
      "compOverride": "Mark as Non-Compliant",
      "nonNeg": true,
      "analystNotes": "Escalate — fails our SSO requirement."
    }
  }
}
```

Use JSON for archiving, audit trails, or sharing with your information
security team. Re-importing the JSON restores both halves: vendor
responses and analyst overrides.

### Export CSV

Exports a `.csv` file with one row per question, including ID, question text,
section, importance, response, notes, expected compliant response, score
mapping, and the four analyst-override columns (Importance Override,
Compliance Override, Non-Negotiable, Analyst Notes). Suitable for importing
into spreadsheet tools and for round-tripping analyst overrides between
reviewers. Re-importing the CSV restores both responses and overrides.

> **Formula injection protection:** Any cell value beginning with `= + - @`
> is automatically prefixed with a single quote so spreadsheet applications
> treat it as plain text rather than a formula.

### Export Excel (for vendors)

**Export HECVAT** (Excel) produces a completed copy of the **official EDUCAUSE HECVAT
4.1.6 workbook** — not a stripped-down rebuild. The tool starts from the real
workbook bundled with this app and injects only your answers into the vendor
answer cells, leaving everything else untouched:

- Every native **formula**, the hidden **scoring engine**, and all
  cross-sheet references are preserved, so scores and compliance verdicts
  recompute themselves when the file is opened.
- The **Yes / No / N/A dropdowns**, conditional formatting, and sheet layout
  are exactly as EDUCAUSE ships them.
- Your answers go into column **C** (response) and column **D** (additional
  info) on the eight vendor sheets, matched to each question by its ID.
- The workbook is flagged to **recalculate on open**, so the institution
  receiving it sees live numbers without any copy-paste.

This is the format a vendor fills out and hands to the institutions assessing
them — anyone who prefers the canonical Excel tool gets a ready-to-submit file
instead of having to transcribe answers by hand. Analyst-only fields are *not*
written to this file; it is purely the vendor's response document.

> Because the export is the official workbook, it round-trips back through
> **Import HECVAT** (Excel), and opens in Excel, LibreOffice, and Google Sheets with the
> scoring intact.

### Evaluator initials

The header has an **Evaluator initials** field. Initials make evaluator
hand-offs traceable:

- They are written at the **end of the JSON and CSV exports** (a top-level
  `evaluatorInitials` key in JSON; a trailing `# Evaluator Initials` row in
  CSV).
- When you **merge** someone else's JSON/CSV into your copy (see below), each
  comment that file contributes is **prefixed with that file's initials**
  (e.g. `[JD] Needs MFA before launch`), so you can see who said what.

Initials are intentionally **not** written into the vendor Excel export.

**Where initials are stored.** Your initials identify the person who made a
given judgement about a named vendor, so they are treated as confidential and
kept only in memory for the session and inside the **encrypted** save envelope
alongside the judgements themselves. They are deliberately not written to
browser storage in the clear, because recording *who assessed whom* in plain
text while encrypting the findings would defeat the point.

Practical consequence: **initials do not survive a page reload on their own.**
Use **Take Snapshot** to persist them, and **Restore Snapshot** to bring them
back. If an earlier version of this tool left a plaintext copy in your
browser, it is adopted once on first load and then deleted from disk.

### Import limits

Imported files come from vendors and are treated as untrusted. Three limits
apply to **every** import format:

| Limit | Value | Why |
|---|---|---|
| File size | 20 MB | Blocks zip bombs and oversized payloads |
| Files per group import | 25 | A review team, not a crowd |
| Records per file | 2,000 | The real form has 332 questions |

The record limit is the one that matters most: it bounds the validation work
before any of it runs, so a small file claiming tens of thousands of records
cannot lock up the page. A genuine assessment is never near any of these.

### Importing & merging

**Import JSON**, **Import CSV**, and **Import HECVAT** (Excel) bring answers back into the
form. Imports **merge** — they never silently overwrite your work:

- A non-empty answer in the file fills in or updates the matching question; a
  blank field in the file will **not** erase an answer you have already typed.
- **Comments are combined, not replaced** — an imported note is appended to any
  note you already have (and re-importing the same file is idempotent, so notes
  never pile up duplicates).
- For evaluator JSON/CSV files, imported comments are labelled with the source
  file's **evaluator initials** so multiple reviewers can be consolidated into
  one copy with clear attribution.

This lets two or more evaluators work in parallel and then merge their copies
together, or lets an evaluator merge a vendor's submission into a working copy
without losing their own annotations.

### Print

Opens the browser print dialog. The sidebar, score banner, and navigation
controls are hidden in print view, and all sections are expanded for a clean
multi-page output, including the vendor-notes appendix, which starts on a
fresh page.

**Printing an analyst tab is not vendor-safe.** Printing shows whichever
section is on screen and expands everything inside it, so printing from an
analyst evaluation tab puts importance overrides, compliance overrides,
non-negotiable flags, and analyst notes on the page. Those tabs therefore
print with a red **INTERNAL — ANALYST USE ONLY. DO NOT SEND TO THE VENDOR.**
banner at the top of the output. It appears only in print, never on screen.
To produce a copy for the vendor, print from a vendor response section or use
**Export HECVAT** instead.

> **Security reminder:** Exported files are **plaintext**. Treat them as
> confidential documents — store them securely, transmit only over encrypted
> channels (e.g. TLS/HTTPS), and delete them when no longer needed.

---

## Accessibility

This form was built to meet WCAG 2.1 AA. Key features:

- **Skip to main content** link at the top of every page
- Every interactive element has a unique, descriptive `aria-label` that
  includes the associated question text — screen readers announce the full
  context of each button. Multi-section sync checkboxes carry the question
  ID so every form field has a distinct accessible name (e.g. `"Sync GNRL-01
  with other sections"`)
- Yes / No button groups use `role="group"` with `aria-labelledby` pointing
  to the question text element; selected state is announced via
  `aria-pressed`
- A **visual tooltip** appears above button groups when they receive keyboard
  focus, showing the question text for sighted keyboard users
- Compliance status indicators use `aria-live="polite"` for screen reader
  announcement
- The running score banner uses `role="status"` and `aria-live="polite"`
- Section panels use `role="region"` with `aria-labelledby`
- Sidebar navigation supports **Arrow Up / Arrow Down** key navigation between
  sections
- Critical questions are marked with a ★ badge and a distinct left border
- Colour is never the sole means of conveying information — Yes/No buttons
  also carry an icon (✓ / ✗) and a corner pip in the selected state; the
  pairwise significance heatmap uses `ns / * / ** / ***` text labels on top
  of its color coding

### Compliance plot accessibility

The three SVG charts on the Institution Evaluation tab are fully accessible:

- Each chart is a `<figure role="figure">` with a `<figcaption>` linked via
  `aria-labelledby`
- Each SVG has `<title>` and `<desc>` **first children**, providing the
  `role="img"` accessible name/description with a prose narration of every
  data point
- Every `<rect>` (bar, stack segment, heatmap cell) has its own nested
  `<title>` with the exact numbers for that element
- Each figure has a **"View data as table"** toggle revealing a semantic
  `<table>` with `<caption>`, `<th scope="col">`, `<th scope="row">`, and
  the same data in tabular form — the reliable alternative when SVG
  narration isn't enough
- Each figure has a **keyboard-accessible zoom toolbar** (− / % / + /
  Reset) that scales the SVG from 50% to 300%; the zoom percentage has
  `aria-live="polite"` so changes are announced
- SVG hosts are `tabindex="0"` with a visible focus ring, so keyboard users
  can tab to a chart to hear its summary

---

## Security Architecture

| Control | Implementation |
|---------|---------------|
| Snapshot encryption | AES-256-GCM via Web Crypto API |
| Evaluator identity | Initials held in memory and in the encrypted envelope only — never written to storage in the clear |
| Printed analyst output | Every analyst evaluation prints with an INTERNAL — DO NOT SEND TO THE VENDOR banner |
| Encryption key storage | sessionStorage only (tab-scoped, not persisted) |
| Plaintext fallback | None — the snapshot is rejected if Web Crypto is unavailable |
| Input validation on load | Shape, type, length, and tag-injection checks on every record |
| DOM XSS prevention | All user content written via `createTextNode`/`textContent`/`.value`; `innerHTML` is never used, so vendor text renders verbatim and markup in it cannot execute |
| CSV formula injection | OWASP prefix mitigation (`'`) on cells starting with `= + - @ \t \r` |
| Attribute injection | `attr()` helper blocks `on*` event-handler attributes and `javascript:` URLs |
| Content Security Policy | `default-src 'self'` · `script-src 'self'` · `style-src 'self'` · `img-src 'self' data:` · `object-src 'none'` · `base-uri 'self'` · `form-action 'none'` · `frame-ancestors 'none'` |
| No external dependencies | Zero network requests — no CDN scripts, no remote fonts, no analytics |

### Bundled third-party libraries

Both libraries are vendored locally and loaded with `script-src 'self'`; the
tool never fetches them from a CDN. Record of what is committed, so the files
can be verified independently:

| File | Library | Version | Source | SHA-256 |
|---|---|---|---|---|
| `xlsx.mini.min.js` | SheetJS Community Edition | 0.20.3 | `https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.mini.min.js` | `0cb353f830d7288385492c83d277b058ddeac664ca51cf1393aa1fd3e2b70939` |
| `fflate.min.js` | fflate (UMD build) | see file header | vendored | `462ef8041fc970e3615a20a9dd2b2e3047a073b2da729ef4f02b634bba8b7b83` |

Verify a copy with `sha256sum xlsx.mini.min.js`.

**Keep SheetJS current.** It parses vendor-supplied `.xlsx` files, which are
untrusted input, so it is the highest-value dependency to patch. Versions
before 0.19.3 carry a prototype-pollution advisory and versions before 0.20.2
carry a regular-expression denial-of-service advisory; 0.20.3 clears both.
SheetJS Community Edition is no longer published to npm, so upgrades mean
downloading a new build from `cdn.sheetjs.com`, replacing the file, and
re-running an import round-trip through both the worker and the
main-thread fallback path.

### Spreadsheet parsing and the worker sandbox

Vendor `.xlsx` files are parsed inside a Web Worker, which has its own global
scope, so a malformed or hostile workbook cannot reach the page holding the
assessment. That isolation is **best effort**, and it is worth knowing when it
is absent.

Browsers refuse to start a worker from a `file://` page, which is the mode
this README recommends first. When that happens the tool parses on the main
thread instead and shows a message saying the sandbox was unavailable. The
same fallback now also covers a worker that starts but cannot run, which
previously failed the import outright.

| Situation | Parsed where | Told to the user |
|---|---|---|
| Served over http or https | Worker | Nothing, this is the normal path |
| Opened from a file path | Main thread | Yes, once per session |
| Worker starts but fails | Main thread | Yes, once per session, with the worker's reason |
| Worker hangs past 30 seconds | Nowhere, import fails | Yes, as an error |

A hanging worker is deliberately **not** retried on the main thread. A file
that hangs the sandbox is exactly the file you do not want to then run
without one.

There is no Blob-worker middle tier. A worker has to `importScripts` the
280 KB parser, and a `file://` page cannot hand it that script for the same
origin reason that blocks the worker in the first place.

If you are handed a workbook you have reason to distrust, open the tool from
a web address rather than a file path and the isolation comes back. Keeping
SheetJS patched matters either way, because the main thread is where it runs
whenever the sandbox is unavailable.

### Deploying behind nginx

nginx inherits `add_header` from an outer level **only if** the current level
declares none of its own, and a regex `location` takes precedence over the
prefix `location /`. So the common pattern of putting security headers in
`location /` and a `Cache-Control` header in `location ~* \.html$` silently
serves HTML, JS and CSS with **no security headers at all**.

The supplied `nginx.conf` avoids this by declaring every header once at
`server{}` level and driving Cache-Control from a `map` variable, so no
location block ever declares an `add_header`. After deploying, verify:

```
curl -sI https://your.host/index.html | grep -i content-security-policy
```

If that comes back empty, an `add_header` has been reintroduced inside a
location block. The Apache and Caddy configs are not affected; their header
directives merge across contexts rather than replacing them.

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

The Web Crypto API (`window.crypto.subtle`) is required for snapshots. All
modern browsers listed above support it. If you are in a restricted environment
where Web Crypto is unavailable, use **Export JSON** to preserve your responses
instead — snapshots will be blocked.

---

## About HECVAT

The Higher Education Community Vendor Assessment Toolkit (HECVAT) is developed
and maintained by **EDUCAUSE**. It is the higher education community standard
for assessing the information security and privacy practices of third-party
vendors and cloud service providers.

- HECVAT documentation and tutorials: [educause.edu/HECVAT](https://educause.edu/HECVAT)
- HECVAT Users Community Group: [educause.edu community](https://educause.edu)

This web form is an **unofficial implementation** of the HECVAT 4.1.6
questionnaire for digital-first completion. It is not affiliated with or
endorsed by EDUCAUSE. Always refer to the official HECVAT documentation for
authoritative guidance on question interpretation and submission requirements.

---

*HECVAT™ is a trademark of EDUCAUSE. Copyright © 2025 EDUCAUSE.*

---

## Hosted Deployment Guide

This tool is designed to run as a local file (`file://`) but can be hosted on a web server. When hosted, you **must** serve the security headers as HTTP response headers — the `<meta>` tags in `index.html` are a fallback, but HTTP headers provide stronger and more reliable enforcement.

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
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';` | Prevents XSS, clickjacking, and injection |
| `X-Frame-Options` | `DENY` | Clickjacking defence (complements CSP `frame-ancestors`) |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type confusion attacks |
| `Referrer-Policy` | `no-referrer` | Prevents URLs containing response data from leaking to third parties |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disables browser APIs the tool does not use |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Forces HTTPS (enable once TLS is confirmed working) |

> **Note:** `X-Frame-Options` and `Strict-Transport-Security` cannot be delivered via `<meta>` tags. They must be HTTP headers. The tool's `<meta>` CSP tag is a belt-and-suspenders measure — it does not replace the HTTP header.

### Deployment on Netlify or Cloudflare Pages

1. Copy the runtime tool files (`index.html`, `hecvat-app.js`, `hecvat-data.js`, `hecvat.css`, `hecvat-worker.js`, `xlsx.mini.min.js`, `fflate.min.js`, `hecvat-template.js`) and the `_headers` file into your repository root. (`HECVAT416.xlsx` is source-only and does not need to be deployed.)
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

