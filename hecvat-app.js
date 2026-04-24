/* ============================================================
   HECVAT 4.1.5 — Application Logic
   Depends on: hecvat-data.js  (HECVAT_QUESTIONS global)

   Security model
   ──────────────
   1. localStorage encryption  — AES-256-GCM via Web Crypto API.
      A fresh random key is generated each browser session and kept
      only in sessionStorage (tab-scoped, not persisted across
      sessions).  The ciphertext in localStorage is useless without
      that session key.
      IMPORTANT: This protects data against casual disk/profile
      inspection (local-at-rest protection).  It does NOT protect
      against active same-origin XSS — if the page were compromised
      by script injection, both ciphertext and session key would be
      accessible.  The appropriate mitigations for that risk are the
      CSP header, DOM-API-only rendering, and the attr() allowlist.

   2. Input sanitisation       — all user-supplied strings (notes,
      text responses) are passed through sanitize() before being
      written back into the DOM.  This is a secondary defence; the
      primary defence is using textContent / .value throughout (never
      innerHTML with user data).  sanitize() should not be relied
      upon to make an unsafe sink safe.

   3. Loaded data validation   — loadData() and applyImport() validate
      the shape of every deserialized record before it touches app
      state: keys must match known question IDs, values must be one of
      the permitted enum values or plain text within a length cap, and
      strings containing executable HTML tags are rejected.

   4. attr() allowlist         — the attribute setter uses a strict
      allowlist of permitted attribute names.  Anything not in the
      list is silently dropped with a console warning.

   5. Clear & Reset            — wipes both localStorage AND
      sessionStorage keys, then reloads.

   6. CSP                      — index.html carries a <meta>
      CSP.  If hosted on a web server, the same policy should be
      delivered as an HTTP Content-Security-Policy response header
      for stronger enforcement (meta CSP cannot cover all cases and
      is easier to bypass in some browser configurations).
      Current policy: no eval, no inline scripts/styles, no external
      origins, no framing.  See index.html and the server
      configuration guide in README.md.
   ============================================================ */

/* ================================================================
   SECURITY — CRYPTO & SANITISATION
================================================================ */
var HECVAT_SEC = (function () {
  'use strict';

  var LS_KEY      = 'hecvat415_enc';   // ciphertext in localStorage
  var SS_KEY      = 'hecvat415_key';   // base64 key in sessionStorage
  var MAX_FIELD   = 8000;              // max chars per user string field

  /* ── Sanitise user input before DOM insertion ────────────────── */
  function sanitize(s) {
    if (typeof s !== 'string') return '';
    return s
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#x27;');
  }

  /* ── Validate a loaded response record ───────────────────────── */
  var VALID_VALUES = { 'Yes': 1, 'No': 1, 'N/A': 1 };
  function validateRecord(qid, record) {
    /* qid must look like XXXX-NN */
    if (!/^[A-Z]{2,5}-\d{1,3}$/.test(qid)) return null;
    if (!record || typeof record !== 'object') return null;

    var out = {};

    /* value: must be Yes/No/N/A or a plain string ≤ MAX_FIELD chars */
    if (record.value !== undefined) {
      if (typeof record.value !== 'string') return null;
      var v = record.value;
      if (v.length > MAX_FIELD) return null;
      /* If it looks like a boolean answer it must be an exact match */
      if (v === 'Yes' || v === 'No' || v === 'N/A' || v === '') {
        out.value = v;
      } else {
      /* Free-text: reject strings containing executable HTML patterns
         (script/iframe/object/etc.) but allow harmless angle-bracket
         usage such as technical notes like "value < threshold" or
         generics like Array<T>.
         We match only tags with an alphanumeric tag name — sufficient
         to catch <script>, <img onerror>, <svg>, <iframe> etc. while
         leaving free-standing < characters intact.              */
      var EXEC_TAG = /<\s*\/?\s*(script|iframe|object|embed|form|input|button|link|meta|style|svg|math|details|dialog|template|base)[^a-z0-9]/i;
      if (EXEC_TAG.test(v)) return null;
      out.value = v;
      }
    }

    /* notes: plain text — same executable-tag rejection as value */
    if (record.notes !== undefined) {
      if (typeof record.notes !== 'string') return null;
      if (record.notes.length > MAX_FIELD) return null;
      var EXEC_TAG_N = /<\s*\/?\s*(script|iframe|object|embed|form|input|button|link|meta|style|svg|math|details|dialog|template|base)[^a-z0-9]/i;
      if (EXEC_TAG_N.test(record.notes)) return null;
      out.notes = record.notes;
    }

    return out;
  }

  /* ── Codec helpers ───────────────────────────────────────────── */
  function b64ToArr(b64) {
    var bin = atob(b64), arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  function arrToB64(arr) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)));
  }

  /* ── Key management ─────────────────────────────────────────── */
  function getOrCreateKey() {
    var existing = sessionStorage.getItem(SS_KEY);
    if (existing) {
      return window.crypto.subtle.importKey(
        'raw', b64ToArr(existing), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
      );
    }
    return window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    ).then(function (key) {
      return window.crypto.subtle.exportKey('raw', key).then(function (raw) {
        sessionStorage.setItem(SS_KEY, arrToB64(raw));
        return key;
      });
    });
  }

  /* ── Encrypt R → localStorage ────────────────────────────────── */
  function saveEncrypted(R) {
    if (!window.crypto || !window.crypto.subtle) {
      /* Hard failure — never persist sensitive data unencrypted */
      return Promise.reject(new Error(
        'Web Crypto API is not available in this browser. ' +
        'Saving is disabled to protect sensitive assessment data. ' +
        'Use Export JSON to preserve your responses.'
      ));
    }
    return getOrCreateKey().then(function (key) {
      var iv  = window.crypto.getRandomValues(new Uint8Array(12));
      var enc = new TextEncoder().encode(JSON.stringify(R));
      return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc)
        .then(function (ct) {
          var payload = JSON.stringify({ iv: arrToB64(iv), ct: arrToB64(ct) });
          localStorage.setItem(LS_KEY, payload);
          return {};
        });
    });
  }

  /* ── Decrypt localStorage → R ────────────────────────────────── */
  function loadDecrypted() {
    var raw = localStorage.getItem(LS_KEY);
    if (!raw) return Promise.resolve(null);

    var parsed;
    try { parsed = JSON.parse(raw); } catch (e) { return Promise.reject(new Error('Stored data is corrupt.')); }

    /* Reject any unencrypted blob saved by older versions of this tool */
    if (parsed.plain) {
      return Promise.reject(new Error(
        'Stored data was saved without encryption by an older version and has been rejected. ' +
        'Please use Clear & Reset, then re-enter your responses.'
      ));
    }

    if (!parsed.iv || !parsed.ct) return Promise.reject(new Error('Stored data format unrecognised.'));

    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(new Error('Web Crypto API not available — cannot decrypt stored data.'));
    }

    return getOrCreateKey().then(function (key) {
      var iv = b64ToArr(parsed.iv);
      var ct = b64ToArr(parsed.ct);
      return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct)
        .then(function (pt) {
          return JSON.parse(new TextDecoder().decode(pt));
        });
    });
  }

  /* ── Clear all persisted data ────────────────────────────────── */
  function clearAll() {
    localStorage.removeItem(LS_KEY);
    sessionStorage.removeItem(SS_KEY);
  }

  return { sanitize: sanitize, validateRecord: validateRecord, saveEncrypted: saveEncrypted, loadDecrypted: loadDecrypted, clearAll: clearAll };
}());

(function () {
  'use strict';

  /* ================================================================
     CONFIGURATION
  ================================================================ */

  var SECS = [
    { id: 'start',   lbl: 'Start Here',      desc: 'General information and required routing questions' },
    { id: 'org',     lbl: 'Organization',     desc: 'Company background, documentation and policies' },
    { id: 'product', lbl: 'Product',          desc: 'Application, authentication and data practices' },
    { id: 'infra',   lbl: 'Infrastructure',   desc: 'Hosting, datacenter and infrastructure controls' },
    { id: 'access',  lbl: 'IT Accessibility', desc: 'WCAG compliance and accessibility practices' },
    { id: 'case',    lbl: 'Case-Specific',    desc: 'HIPAA, PCI-DSS, consulting and on-premises' },
    { id: 'ai',      lbl: 'AI',              desc: 'Artificial intelligence features and governance' },
    { id: 'privacy', lbl: 'Privacy',          desc: 'Data privacy controls and analyst review' },
  ];

  /* Section gates: which REQU answer controls whether a section is required */
  var SECTION_GATES = {
    'product': { reqId: 'REQU-01', label: 'REQU-01 — Are you offering a product or platform?' },
    'infra':   { reqId: 'REQU-01', label: 'REQU-01 — Are you offering a product or platform?' },
    'access':  { reqId: 'REQU-02', label: 'REQU-02 — Does your product or service have an interface?' },
    'ai':      { reqId: 'REQU-04', label: 'REQU-04 — Does your solution have AI features?' },
    'privacy': { reqId: 'REQU-08', label: 'REQU-08 — Does your solution have access to personal or institutional data?' },
  };

  var CAT = {
    GNRL: 'General Information',      COMP: 'Company Information',
    REQU: 'Required Questions',       DOCU: 'Documentation',
    ITAC: 'IT Accessibility',         THRD: 'Third-Party Assessments',
    CONS: 'Consulting Services',      APPL: 'Application Controls',
    AAAI: 'Authentication & Access',  CHNG: 'Change Management',
    DATA: 'Data Handling',            DCTR: 'Datacenter Controls',
    FIDP: 'Federation & Identity',    HFIH: 'High-Risk Controls',
    VULN: 'Vulnerability Mgmt',       HIPA: 'HIPAA',
    PCID: 'PCI-DSS',                  OPEM: 'On-Premises',
    PRGN: 'Privacy Governance',       PCOM: 'Privacy Communication',
    PDOC: 'Privacy Documentation',    PTHP: 'Third-Party Privacy',
    PCHG: 'Privacy Change Mgmt',      PDAT: 'Privacy Data',
    PRPO: 'Rights & Opt-Out',         INTL: 'International Transfers',
    DRPV: 'Data Retention & Privacy', DPAI: 'Data Privacy AI',
    AIQU: 'AI Qualification',         AIGN: 'AI Governance',
    AIPL: 'AI Policies',              AISC: 'AI Security',
    AIML: 'AI Machine Learning',      AILM: 'AI Lifecycle Mgmt',
    PPPR: 'Privacy Program',
  };

  /* Pre-index questions by section */
  var SQ = {};
  SECS.forEach(function (s) {
    SQ[s.id] = HECVAT_QUESTIONS.filter(function (q) {
      return q.sections.indexOf(s.id) > -1;
    });
  });

  /* ================================================================
     STATE
  ================================================================ */
  var R = {};                  // responses: { qid: { value, notes } }  (primary / shared value)
  var RS = {};                 // per-section overrides when a secondary instance is UNLINKED
                               //   key = secId + ':' + qid  →  { value, notes }
  var AE = {};                 // analyst evaluations: { qid: { impOverride, compOverride, nonNeg, analystNotes } }
  var renderedIn = {};         // qid -> first secId rendered (authoritative for scoring)
  var xrefRegistry = [];       // [{ qid, el }] live cross-ref display elements (unused now — kept for compat)
  var secondaryReg = {};       // qid -> [ { secId, linked, updateUI(val), updateNotes(n) } ]
                               //   secondary instances that render a full input in other sections

  /* ================================================================
     DOM HELPERS
  ================================================================ */
  function mk(tag, cls) { var e = document.createElement(tag); if (cls) e.className = cls; return e; }
  function txt(s) { return document.createTextNode(s || ''); }
  /* Attribute setter — strict allowlist.
     Only attributes explicitly listed here can be set on generated elements.
     This prevents any future code path from accidentally setting event-handler
     attributes or unsafe URL attributes via this helper.                       */
  var ATTR_ALLOWLIST = {
    /* Universal */
    'id':1,'class':1,'role':1,'tabindex':1,'hidden':1,'title':1,'lang':1,
    /* ARIA */
    'aria-label':1,'aria-labelledby':1,'aria-describedby':1,'aria-hidden':1,
    'aria-live':1,'aria-atomic':1,'aria-expanded':1,'aria-controls':1,
    'aria-pressed':1,'aria-current':1,'aria-checked':1,'aria-selected':1,
    'aria-disabled':1,'aria-required':1,'aria-multiselectable':1,
    /* Form inputs */
    'type':1,'name':1,'value':1,'for':1,'accept':1,'autocomplete':1,
    'checked':1,'disabled':1,'readonly':1,'required':1,'rows':1,'cols':1,
    'min':1,'max':1,'step':1,'minlength':1,'maxlength':1,'placeholder':1,
    'multiple':1,'selected':1,
    /* Links / media — values are checked to exclude javascript: */
    'href':1,'src':1,'alt':1,'download':1,'target':1,'rel':1,
    /* Data attributes (pattern checked below) */
    /* Table */
    'colspan':1,'rowspan':1,'scope':1,
  };

  function attr(e, k, v) {
    /* Allow data-* attributes */
    if (/^data-[a-z][a-z0-9-]*$/.test(k)) {
      e.setAttribute(k, v);
      return e;
    }
    /* Reject anything not in the allowlist */
    if (!ATTR_ALLOWLIST[k]) {
      console.warn('HECVAT: blocked disallowed attribute:', k);
      return e;
    }
    /* Extra URL safety — block javascript: pseudo-protocol in any
       attribute that a browser may resolve as a navigable URL.    */
    var URL_ATTRS = { href:1, src:1, action:1, download:1, formaction:1,
                      poster:1, ping:1, 'xlink:href':1 };
    if (URL_ATTRS[k] && /^\s*javascript:/i.test(String(v))) {
      console.warn('HECVAT: blocked javascript: URL in attribute:', k);
      return e;
    }
    e.setAttribute(k, v);
    return e;
  }
  function getSecLabel(id) { var s = SECS.find(function (x) { return x.id === id; }); return s ? s.lbl : id; }
  function pts(imp) { return imp === 'Critical Importance' ? 20 : imp === 'Minor Importance' ? 5 : 10; }

  /* ================================================================
     BUILD NAV
  ================================================================ */
  function buildNav() {
    var nav = document.getElementById('snav');

    SECS.forEach(function (s, i) {
      var b = mk('button', 'nb' + (i === 0 ? ' active' : ''));
      b.type = 'button'; b.id = 'nb-' + s.id;
      attr(b, 'aria-label', s.lbl + ' section');
      attr(b, 'aria-current', i === 0 ? 'true' : 'false');
      attr(b, 'data-sec', s.id);

      var dot = mk('span', 'nd'); attr(dot, 'aria-hidden', 'true'); b.appendChild(dot);
      b.appendChild(txt(' ' + s.lbl));

      /* "Not Required" tag — hidden until gated */
      var tag = mk('span', 'nb-tag hidden'); tag.id = 'nb-tag-' + s.id;
      tag.appendChild(txt('N/R'));
      b.appendChild(tag);

      var ct = mk('span', 'nc'); ct.id = 'nc-' + s.id; attr(ct, 'aria-hidden', 'true'); ct.textContent = '0';
      b.appendChild(ct);
      nav.appendChild(b);
    });

    /* Summary button */
    var sb = mk('button', 'nb'); sb.type = 'button'; sb.id = 'nb-summary';
    attr(sb, 'aria-label', 'Assessment summary'); attr(sb, 'aria-current', 'false'); attr(sb, 'data-sec', 'summary');
    var sd = mk('span', 'nd'); attr(sd, 'aria-hidden', 'true'); sb.appendChild(sd);
    sb.appendChild(txt(' Summary')); nav.appendChild(sb);

    /* Delegated click */
    nav.addEventListener('click', function (e) {
      var b = e.target.closest('.nb'); if (!b) return;
      goTo(b.getAttribute('data-sec'));
    });

    /* Arrow-key nav */
    nav.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      var btns = [].slice.call(nav.querySelectorAll('.nb'));
      var i = btns.indexOf(document.activeElement); if (i === -1) return;
      var next = btns[e.key === 'ArrowDown' ? i + 1 : i - 1];
      if (next) { next.focus(); e.preventDefault(); }
    });
  }

  /* ================================================================
     BUILD SECONDARY QUESTION INSTANCE
     Rendered when a question's q.sections contains more than one section
     and this is NOT the primary (first) section.  Each instance gets its
     own answerable input plus a "Sync answer with other sections"
     checkbox (default checked).  When linked, edits propagate through
     R[qid] to the primary and other linked instances.  When unlinked,
     edits are stored in RS[secId+':'+qid] and do not affect scoring.
  ================================================================ */
  function buildQSecondary(q, secId, primarySecId) {
    var key = secId + ':' + q.id;

    /* Default: linked (shares master answer).  Per-instance link state
       is tracked on the DOM via aria-pressed on the checkbox, and the
       logical state by whether RS[key] exists and has an override flag. */
    var rec = RS[key] || null;
    var linked = !(rec && rec.unlinked);

    var crit   = q.imp === 'Critical Importance';

    var row = mk('div', 'qrow qrow-sec' + (crit ? ' crit' : ''));
    row.id = 'qrow-' + secId + '-' + q.id;
    attr(row, 'data-qid', q.id);
    attr(row, 'data-sec', secId);

    /* Left column — question meta + text + guidance */
    var L = mk('div');
    var meta = mk('div', 'qmeta');
    meta.appendChild(txt(q.id));
    if (q.imp === 'Critical Importance') {
      var bc = mk('span', 'bdg bdg-c'); bc.textContent = '\u2605 Critical'; meta.appendChild(bc);
    } else if (q.imp === 'Standard Importance') {
      var bs = mk('span', 'bdg bdg-s'); bs.textContent = 'Standard'; meta.appendChild(bs);
    } else if (q.imp === 'Minor Importance') {
      var bm = mk('span', 'bdg bdg-m'); bm.textContent = 'Minor'; meta.appendChild(bm);
    }
    var srcTag = mk('span', 'ref-src-tag');
    srcTag.appendChild(txt('Also in ' + getSecLabel(primarySecId)));
    meta.appendChild(srcTag);
    L.appendChild(meta);

    var qt = mk('div', 'qtext'); qt.id = 'qt-' + secId + '-' + q.id; qt.appendChild(txt(q.q)); L.appendChild(qt);

    if (q.guide) {
      var g = mk('div', 'qguide'); attr(g, 'role', 'note');
      g.id = 'guide-' + secId + '-' + q.id;
      var gIcon = mk('span', 'cg-icon'); attr(gIcon, 'aria-hidden', 'true');
      gIcon.textContent = '\uD83D\uDCA1';
      g.appendChild(gIcon); g.appendChild(txt(q.guide));
      L.appendChild(g);
    }

    /* Sync checkbox — controls whether this instance mirrors R[qid].
       Label is unique per-question so each form field has a distinct
       accessible name (e.g. "Sync GNRL-01 with other sections"). */
    var syncWrap = mk('div', 'sync-wrap');
    var syncCb = document.createElement('input');
    syncCb.type = 'checkbox';
    syncCb.className = 'sync-cb';
    syncCb.id = 'sync-' + secId + '-' + q.id;
    syncCb.checked = linked;
    attr(syncCb, 'aria-label', 'Sync ' + q.id + ' with other sections');
    var syncLbl = mk('label', 'sync-lbl'); syncLbl.htmlFor = syncCb.id;
    syncLbl.appendChild(txt('Sync ' + q.id + ' with other sections'));
    syncWrap.appendChild(syncCb); syncWrap.appendChild(syncLbl);
    L.appendChild(syncWrap);
    row.appendChild(L);

    /* Right column — input */
    var Ri = mk('div');

    /* State helpers — "getVal" returns the value that this instance is
       currently displaying; "writeVal" writes the value to the proper
       store based on current link state. */
    function getVal() {
      if (linked) return (R[q.id] && R[q.id].value) || '';
      return (RS[key] && RS[key].value) || '';
    }
    function getNotes() {
      if (linked) return (R[q.id] && R[q.id].notes) || '';
      return (RS[key] && RS[key].notes) || '';
    }
    function writeVal(v) {
      if (linked) {
        R[q.id] = R[q.id] || {};
        if (v === undefined) delete R[q.id].value; else R[q.id].value = v;
      } else {
        RS[key] = RS[key] || { unlinked: true };
        if (v === undefined) delete RS[key].value; else RS[key].value = v;
      }
    }
    function writeNotes(v) {
      if (linked) {
        R[q.id] = R[q.id] || {};
        R[q.id].notes = v;
      } else {
        RS[key] = RS[key] || { unlinked: true };
        RS[key].notes = v;
      }
    }

    /* The render/update closures are built per-type below and stored on
       the secondary registry entry so pickAnswer() can update this
       instance when the master value changes. */
    var updateUI, updateNotesUI;

    if (q.type === 'select') {
      var selLbl = mk('label', 'flbl');
      selLbl.htmlFor = 'fi-' + secId + '-' + q.id;
      selLbl.appendChild(txt('Response'));
      Ri.appendChild(selLbl);

      var selEl = mk('select', 'analyst-select');
      selEl.id = 'fi-' + secId + '-' + q.id;
      attr(selEl, 'aria-labelledby', 'qt-' + secId + '-' + q.id);
      var blankOpt = document.createElement('option');
      blankOpt.value = ''; blankOpt.textContent = '-- Select an option --';
      selEl.appendChild(blankOpt);
      (q.options || []).forEach(function (opt) {
        var o = document.createElement('option'); o.value = opt; o.textContent = opt;
        selEl.appendChild(o);
      });
      selEl.value = getVal();
      selEl.addEventListener('change', function () {
        writeVal(selEl.value);
        if (linked) { propagateLinkedValue(q.id, selEl.value, secId); checkGates(); }
        refreshProgress();
      });
      Ri.appendChild(selEl);
      updateUI = function (v) { selEl.value = v || ''; };

    } else if (q.type === 'text' || q.type === 'textarea') {
      var inputType = 'text';
      if (q.type === 'text') {
        var ql = q.q.toLowerCase();
        if      (ql.indexOf('email') > -1)                          inputType = 'email';
        else if (ql.indexOf('phone') > -1)                          inputType = 'tel';
        else if (ql.indexOf('link') > -1 || ql.indexOf('url') > -1) inputType = 'url';
      }
      var lbl = mk('label', 'flbl');
      lbl.htmlFor = 'fi-' + secId + '-' + q.id;
      lbl.appendChild(txt('Response'));
      Ri.appendChild(lbl);

      var inp = q.type === 'textarea' ? mk('textarea') : document.createElement('input');
      if (q.type === 'text') inp.type = inputType;
      inp.id = 'fi-' + secId + '-' + q.id;
      attr(inp, 'aria-labelledby', 'qt-' + secId + '-' + q.id);
      if (q.type === 'text') inp.autocomplete = 'off'; else inp.rows = 3;
      inp.value = getVal();
      inp.addEventListener('input', function () {
        writeVal(inp.value);
        if (linked) { propagateLinkedValue(q.id, inp.value, secId); checkGates(); }
        refreshProgress();
      });
      Ri.appendChild(inp);
      updateUI = function (v) { inp.value = v || ''; };

    } else {
      /* Yes / No */
      var wrap = mk('div', 'yng-wrap');
      var grp = mk('div', 'yng'); attr(grp, 'role', 'group');
      attr(grp, 'aria-labelledby', 'qt-' + secId + '-' + q.id);

      var btnMap = {};
      ['Yes', 'No'].forEach(function (v) {
        var vk = v.toLowerCase();
        var btn = mk('button', 'ynb ynb-' + vk);
        btn.type = 'button';
        btn.id = 'yn-' + vk + '-' + secId + '-' + q.id;
        attr(btn, 'aria-pressed', 'false');
        attr(btn, 'data-qid', q.id);
        attr(btn, 'data-val', v);
        attr(btn, 'data-sec', secId);
        attr(btn, 'aria-label', (v === 'Yes' ? 'Yes \u2014 ' : 'No \u2014 ') + q.q);
        var icon = mk('span'); attr(icon, 'aria-hidden', 'true');
        icon.appendChild(txt(v === 'Yes' ? '\u2713 Yes' : '\u2717 No'));
        btn.appendChild(icon);
        btn.addEventListener('click', function () {
          var cur = getVal();
          if (cur === v) {
            writeVal(undefined);
            applyYesNoDisplay('');
            if (linked) { propagateLinkedValue(q.id, '', secId); checkGates(); }
          } else {
            writeVal(v);
            applyYesNoDisplay(v);
            if (linked) { propagateLinkedValue(q.id, v, secId); checkGates(); }
          }
          refreshProgress();
        });
        btnMap[v] = btn;
        grp.appendChild(btn);
      });
      wrap.appendChild(grp);
      Ri.appendChild(wrap);

      /* Compliance indicator */
      var ci = mk('div', 'cind');
      ci.id = 'ci-' + secId + '-' + q.id;
      attr(ci, 'role', 'status'); attr(ci, 'aria-live', 'polite');
      Ri.appendChild(ci);

      function applyYesNoDisplay(val) {
        Object.keys(btnMap).forEach(function (kk) {
          var b = btnMap[kk];
          b.classList.remove('sel-y', 'sel-n');
          attr(b, 'aria-pressed', 'false');
        });
        if (val === 'Yes') { btnMap['Yes'].classList.add('sel-y'); attr(btnMap['Yes'], 'aria-pressed', 'true'); }
        else if (val === 'No') { btnMap['No'].classList.add('sel-n'); attr(btnMap['No'], 'aria-pressed', 'true'); }

        var scorable = (q.comp === 'Yes' || q.comp === 'No') &&
                       q.loc !== 'Not Scored' && q.score !== 'NA';
        ci.className = 'cind'; ci.textContent = '';
        if (!scorable || !val) { /* leave hidden */ }
        else if (val === q.comp) { ci.className = 'cind on ok'; ci.textContent = '\u2713 Compliant response'; }
        else { ci.className = 'cind on bad'; ci.textContent = '\u2717 Non-compliant response'; }
      }
      applyYesNoDisplay(getVal());
      updateUI = applyYesNoDisplay;
    }

    /* Notes */
    var tog = mk('button', 'ntog'); tog.type = 'button';
    attr(tog, 'aria-expanded', 'false');
    attr(tog, 'aria-controls', 'na-' + secId + '-' + q.id);
    attr(tog, 'aria-label', 'Add notes for ' + q.id);
    tog.appendChild(txt('+ Add notes'));
    tog.addEventListener('click', function () {
      var open = tog.getAttribute('aria-expanded') === 'true';
      attr(tog, 'aria-expanded', String(!open));
      area.classList.toggle('on', !open);
      tog.firstChild.textContent = open ? '+ Add notes' : '\u2212 Hide notes';
    });
    Ri.appendChild(tog);

    var area = mk('div', 'narea'); area.id = 'na-' + secId + '-' + q.id;
    attr(area, 'role', 'region');
    var nlbl = mk('label', 'flbl'); nlbl.htmlFor = 'ni-' + secId + '-' + q.id;
    nlbl.appendChild(txt('Notes / Context'));
    area.appendChild(nlbl);
    var nta = mk('textarea', 'notes-ta');
    nta.id = 'ni-' + secId + '-' + q.id; nta.rows = 2;
    attr(nta, 'aria-labelledby', 'qt-' + secId + '-' + q.id);
    nta.value = getNotes();
    nta.addEventListener('input', function () {
      writeNotes(nta.value);
      if (linked) propagateLinkedNotes(q.id, nta.value, secId);
    });
    area.appendChild(nta);
    Ri.appendChild(area);

    row.appendChild(Ri);

    updateNotesUI = function (n) { nta.value = n || ''; };

    /* Register so pickAnswer / input handlers can update this instance */
    var instance = {
      secId: secId,
      isLinked: function () { return linked; },
      updateUI: function (v) { updateUI(v); },
      updateNotesUI: function (n) { updateNotesUI(n); },
    };
    secondaryReg[q.id] = secondaryReg[q.id] || [];
    secondaryReg[q.id].push(instance);

    /* Sync checkbox wiring: toggle link state; when linking, adopt
       the master value (and discard the per-section override). */
    syncCb.addEventListener('change', function () {
      linked = syncCb.checked;
      if (linked) {
        delete RS[key];
        /* Pull master value into this instance's UI */
        var mv = (R[q.id] && R[q.id].value) || '';
        updateUI(mv);
        var mn = (R[q.id] && R[q.id].notes) || '';
        updateNotesUI(mn);
      } else {
        /* Persist current master value as starting point for local edits */
        RS[key] = { unlinked: true,
                    value: (R[q.id] && R[q.id].value) || '',
                    notes: (R[q.id] && R[q.id].notes) || '' };
      }
      row.classList.toggle('unlinked', !linked);
      refreshProgress();
    });
    row.classList.toggle('unlinked', !linked);

    return row;
  }

  /* Propagate a value change originating in one instance to all OTHER
     linked instances (primary + linked secondaries) of the same qid. */
  function propagateLinkedValue(qid, val, fromSecId) {
    /* Primary section uses unscoped DOM IDs */
    syncPrimaryDisplay(qid, val);
    /* Linked secondaries */
    var insts = secondaryReg[qid] || [];
    insts.forEach(function (ii) {
      if (ii.secId === fromSecId) return;
      if (ii.isLinked()) ii.updateUI(val);
    });
  }
  function propagateLinkedNotes(qid, notes, fromSecId) {
    /* Primary section notes textarea */
    var primaryNi = document.getElementById('ni-' + qid);
    if (primaryNi && primaryNi.value !== notes) primaryNi.value = notes;
    var insts = secondaryReg[qid] || [];
    insts.forEach(function (ii) {
      if (ii.secId === fromSecId) return;
      if (ii.isLinked()) ii.updateNotesUI(notes);
    });
  }

  /* Update the PRIMARY section's DOM to reflect a value set elsewhere */
  function syncPrimaryDisplay(qid, val) {
    var q = HECVAT_QUESTIONS.find(function (x) { return x.id === qid; });
    if (!q) return;

    if (q.type === 'select' || q.type === 'text' || q.type === 'textarea') {
      var fi = document.getElementById('fi-' + qid);
      if (fi && fi.value !== (val || '')) fi.value = val || '';
      return;
    }
    /* Yes/No/N/A — update button classes + aria-pressed + guidance + compliance.
       Element IDs use full-word suffixes; selection classes are single-letter. */
    ['yes', 'no', 'na'].forEach(function (vk) {
      var btn = document.getElementById('yn-' + vk + '-' + qid);
      if (!btn) return;
      btn.classList.remove('sel-y', 'sel-n', 'sel-na');
      attr(btn, 'aria-pressed', 'false');
    });
    if (val === 'Yes')     { var b1 = document.getElementById('yn-yes-' + qid); if (b1) { b1.classList.add('sel-y');  attr(b1, 'aria-pressed', 'true'); } }
    else if (val === 'No') { var b2 = document.getElementById('yn-no-'  + qid); if (b2) { b2.classList.add('sel-n');  attr(b2, 'aria-pressed', 'true'); } }
    else if (val === 'N/A'){ var b3 = document.getElementById('yn-na-'  + qid); if (b3) { b3.classList.add('sel-na'); attr(b3, 'aria-pressed', 'true'); } }

    var yg = document.getElementById('yg-' + qid);
    var ng = document.getElementById('ng-' + qid);
    if (yg) { yg.classList.toggle('on', val === 'Yes'); attr(yg, 'aria-hidden', val === 'Yes' ? 'false' : 'true'); }
    if (ng) { ng.classList.toggle('on', val === 'No');  attr(ng, 'aria-hidden', val === 'No'  ? 'false' : 'true'); }

    var ci = document.getElementById('ci-' + qid);
    if (ci) {
      var scorable = (q.comp === 'Yes' || q.comp === 'No') &&
                     q.loc !== 'Not Scored' && q.score !== 'NA';
      ci.className = 'cind'; ci.textContent = '';
      if (!scorable || !val) { /* hidden */ }
      else if (val === 'N/A')       { ci.className = 'cind on neu'; ci.textContent = '\u2014 N/A \u2014 Not applicable'; }
      else if (val === q.comp)      { ci.className = 'cind on ok';  ci.textContent = '\u2713 Compliant response'; }
      else                          { ci.className = 'cind on bad'; ci.textContent = '\u2717 Non-compliant response'; }
    }
  }

  function syncXrefDisplay(el, qid) {
    var val = R[qid] && R[qid].value;
    /* Clear element safely — no innerHTML, all content via textContent */
    while (el.firstChild) el.removeChild(el.firstChild);
    el.className = 'ref-answer';
    if (!val) {
      el.appendChild(txt('Not yet answered'));
      el.classList.add('ref-empty');
    } else if (val === 'Yes') {
      el.appendChild(txt('\u2713 Yes'));  el.classList.add('ref-yes');
    } else if (val === 'No') {
      el.appendChild(txt('\u2717 No'));   el.classList.add('ref-no');
    } else if (val === 'N/A') {
      el.appendChild(txt('\u2014 N/A'));  el.classList.add('ref-na');
    } else {
      /* User free-text: sanitise then truncate for display */
      var safe = HECVAT_SEC.sanitize(val);
      el.appendChild(txt(safe.length > 70 ? safe.slice(0, 70) + '\u2026' : safe));
      el.classList.add('ref-txt');
    }
  }

  function refreshXrefs() {
    xrefRegistry.forEach(function (x) { syncXrefDisplay(x.el, x.qid); });
  }

  /* ================================================================
     BUILD FULL QUESTION ROW
  ================================================================ */
  function buildQ(q, secId) {
    /* Already rendered in an earlier section? Render an independent
       answerable instance with a sync checkbox (default: linked). */
    if (renderedIn[q.id] !== undefined) {
      return buildQSecondary(q, secId, renderedIn[q.id]);
    }
    renderedIn[q.id] = secId;

    var crit   = q.imp === 'Critical Importance';
    var scored = q.score !== 'NA' && q.loc !== 'Not Scored';

    var row = mk('div', 'qrow' + (crit ? ' crit' : ''));
    row.id = 'qrow-' + q.id;
    attr(row, 'data-qid', q.id);

    /* ── Left column ── */
    var L = mk('div');

    var meta = mk('div', 'qmeta');
    meta.appendChild(txt(q.id));
    if (q.imp === 'Critical Importance') {
      var bc = mk('span', 'bdg bdg-c'); bc.textContent = '\u2605 Critical'; meta.appendChild(bc);
    } else if (q.imp === 'Standard Importance') {
      var bs = mk('span', 'bdg bdg-s'); bs.textContent = 'Standard'; meta.appendChild(bs);
    } else if (q.imp === 'Minor Importance') {
      var bm = mk('span', 'bdg bdg-m'); bm.textContent = 'Minor'; meta.appendChild(bm);
    }
    L.appendChild(meta);

    /* Question text — given an ID so buttons can reference it via aria-labelledby */
    var qt = mk('div', 'qtext'); qt.id = 'qt-' + q.id; qt.appendChild(txt(q.q)); L.appendChild(qt);

    if (q.guide) {
      var g = mk('div', 'qguide'); attr(g, 'role', 'note');
      var guideId = 'guide-' + q.id;
      g.id = guideId;
      var gIcon = mk('span', 'cg-icon'); attr(gIcon, 'aria-hidden', 'true');
      gIcon.textContent = '\uD83D\uDCA1'; /* 💡 */
      g.appendChild(gIcon);
      g.appendChild(txt(q.guide)); L.appendChild(g);
    }
    if (q.yesG) {
      var yg = mk('div', 'cg yg'); yg.id = 'yg-' + q.id;
      attr(yg, 'role', 'note'); attr(yg, 'aria-live', 'polite'); attr(yg, 'aria-hidden', 'true');
      attr(yg, 'aria-label', 'Guidance for Yes answer on ' + q.id);
      var ygIcon = mk('span', 'cg-icon'); attr(ygIcon, 'aria-hidden', 'true');
      ygIcon.textContent = '\u2713'; /* ✓ */
      yg.appendChild(ygIcon);
      yg.appendChild(txt(q.yesG)); L.appendChild(yg);
    }
    if (q.noG) {
      var ng = mk('div', 'cg ng'); ng.id = 'ng-' + q.id;
      attr(ng, 'role', 'note'); attr(ng, 'aria-live', 'polite'); attr(ng, 'aria-hidden', 'true');
      attr(ng, 'aria-label', 'Guidance for No answer on ' + q.id);
      var ngIcon = mk('span', 'cg-icon'); attr(ngIcon, 'aria-hidden', 'true');
      ngIcon.textContent = '\u2715'; /* ✕ */
      ng.appendChild(ngIcon);
      ng.appendChild(txt(q.noG)); L.appendChild(ng);
    }
    row.appendChild(L);

    /* ── Right column: input ── */
    var Ri = mk('div');

    if (q.type === 'select') {
      /* ── Dropdown select (e.g. DCTR-01 hosting option) ── */
      var selLbl = mk('label', 'flbl');
      selLbl.htmlFor = 'fi-' + q.id;
      selLbl.appendChild(txt('Response'));
      var selLblSr = mk('span', 'sr-only');
      selLblSr.appendChild(txt(' for: ' + q.q));
      selLbl.appendChild(selLblSr);
      Ri.appendChild(selLbl);

      var selEl = mk('select', 'analyst-select');
      selEl.id = 'fi-' + q.id;
      attr(selEl, 'data-qid', q.id);
      attr(selEl, 'aria-labelledby', 'qt-' + q.id);
      if (q.guide) attr(selEl, 'aria-describedby', 'guide-' + q.id);
      var blankOpt = document.createElement('option');
      blankOpt.value = ''; blankOpt.textContent = '-- Select an option --';
      selEl.appendChild(blankOpt);
      (q.options || []).forEach(function (opt) {
        var o = document.createElement('option'); o.value = opt; o.textContent = opt;
        selEl.appendChild(o);
      });
      Ri.appendChild(selEl);

    } else if (q.type === 'text' || q.type === 'textarea') {
      /* ── Text / textarea input ── */
      var inputType = 'text';
      if (q.type === 'text') {
        var ql = q.q.toLowerCase();
        if      (ql.indexOf('email') > -1)                           inputType = 'email';
        else if (ql.indexOf('phone') > -1)                           inputType = 'tel';
        else if (ql.indexOf('link') > -1 || ql.indexOf('url') > -1) inputType = 'url';
      }

      /* Unique label — references the question text span */
      var lbl = mk('label', 'flbl');
      lbl.htmlFor = 'fi-' + q.id;
      lbl.appendChild(txt('Response'));
      /* Screen-reader addition: includes question text */
      var lblSr = mk('span', 'sr-only');
      lblSr.appendChild(txt(' for: ' + q.q));
      lbl.appendChild(lblSr);
      Ri.appendChild(lbl);

      var inp = q.type === 'textarea' ? mk('textarea') : document.createElement('input');
      if (q.type === 'text') inp.type = inputType;
      inp.id = 'fi-' + q.id;
      attr(inp, 'data-qid', q.id);
      /* aria-labelledby combines label + question text for full context */
      attr(inp, 'aria-labelledby', 'qt-' + q.id);
      if (q.guide) attr(inp, 'aria-describedby', 'guide-' + q.id);
      if (q.type === 'text') inp.autocomplete = 'off';
      else inp.rows = 3;
      Ri.appendChild(inp);

    } else {
      /* ── Yes / No / N/A toggle group ── */
      var wrap = mk('div', 'yng-wrap');

      /* Focus tooltip: shows question text visually when group has keyboard focus.
         aria-hidden because screen readers already get question text via aria-labelledby */
      var tooltip = mk('div', 'yng-tooltip');
      attr(tooltip, 'aria-hidden', 'true');
      tooltip.appendChild(txt(q.q));
      wrap.appendChild(tooltip);

      var grp = mk('div', 'yng');
      attr(grp, 'role', 'group');
      /* Group is labelled by the question text element */
      attr(grp, 'aria-labelledby', 'qt-' + q.id);

      var rlbl = mk('span', 'flbl');
      /* Screen readers read both this "Response" label and the question text via aria-labelledby */
      rlbl.id = 'rl-' + q.id;
      rlbl.appendChild(txt('Response'));
      wrap.appendChild(rlbl);

      /* Yes / No — only binary answers are offered */
      ['Yes', 'No'].forEach(function (v) {
        var vk  = v.toLowerCase();
        var btn = mk('button', 'ynb ynb-' + vk);
        btn.type = 'button';
        btn.id   = 'yn-' + vk + '-' + q.id;
        attr(btn, 'aria-pressed', 'false');
        attr(btn, 'data-qid', q.id);
        attr(btn, 'data-val', v);

        /* Full unique accessible label = action + question text */
        attr(btn, 'aria-label', (v === 'Yes' ? 'Yes \u2014 ' : 'No \u2014 ') + q.q);

        /* Visible text (icon only — question context comes via tooltip on focus) */
        var icon = mk('span'); attr(icon, 'aria-hidden', 'true');
        icon.appendChild(txt(v === 'Yes' ? '\u2713 Yes' : '\u2717 No'));
        btn.appendChild(icon);

        grp.appendChild(btn);
      });

      wrap.appendChild(grp);
      Ri.appendChild(wrap);

      /* Compliance indicator */
      var ci = mk('div', 'cind');
      ci.id = 'ci-' + q.id;
      attr(ci, 'role', 'status');
      attr(ci, 'aria-live', 'polite');
      attr(ci, 'aria-label', 'Compliance status for ' + q.id);
      Ri.appendChild(ci);
    }

    /* Notes toggle — ALL questions get this */
    var tog = mk('button', 'ntog');
    tog.type = 'button';
    attr(tog, 'aria-expanded', 'false');
    attr(tog, 'aria-controls', 'na-' + q.id);
    attr(tog, 'data-notes-for', q.id);
    /* Unique label includes question context */
    attr(tog, 'aria-label', 'Add notes for ' + q.id + ': ' + q.q);
    tog.appendChild(txt('+ Add notes'));
    Ri.appendChild(tog);

    var area = mk('div', 'narea'); area.id = 'na-' + q.id;
    attr(area, 'role', 'region');
    attr(area, 'aria-label', 'Notes for ' + q.id);

    var nlbl = mk('label', 'flbl'); nlbl.htmlFor = 'ni-' + q.id;
    nlbl.appendChild(txt('Notes / Context'));
    var nlblSr = mk('span', 'sr-only');
    nlblSr.appendChild(txt(' for ' + q.id + ': ' + q.q));
    nlbl.appendChild(nlblSr);
    area.appendChild(nlbl);

    var nta = mk('textarea', 'notes-ta');
    nta.id = 'ni-' + q.id; nta.rows = 2;
    attr(nta, 'data-notes-qid', q.id);
    attr(nta, 'aria-labelledby', 'qt-' + q.id);
    area.appendChild(nta);

    Ri.appendChild(area);
    row.appendChild(Ri);
    return row;
  }

  /* ================================================================
     SHARED COLLAPSIBLE H3 CATEGORY BUILDER
     Used by vendor response sections, Institution Evaluation,
     High-Risk, and Privacy Analyst panels.
  ================================================================ */
  function mkCollapsible(label, count, buildRows, uid) {
    uid = uid || ('cat-' + label.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 40));
    var bodyId = uid + '-body';

    var sec = mk('div', 'cat-sec');

    /* H3 wrapping the toggle button */
    var h3 = mk('h3', 'cat-h3');
    var togBtn = mk('button', 'cat-tog');
    togBtn.type = 'button';
    attr(togBtn, 'aria-expanded', 'true');
    attr(togBtn, 'aria-controls', bodyId);

    var togLbl = mk('span', 'cat-tog-lbl'); togLbl.appendChild(txt(label));
    var togBadge = mk('span', 'cat-ct'); togBadge.textContent = String(count);
    var togIcon = mk('span', 'cat-tog-icon'); attr(togIcon, 'aria-hidden', 'true'); togIcon.textContent = '\u25BE';

    togBtn.appendChild(togLbl);
    togBtn.appendChild(togBadge);
    togBtn.appendChild(togIcon);
    h3.appendChild(togBtn);
    sec.appendChild(h3);

    /* Collapsible body — role="region" labelled by the H3 */
    var body = mk('div', 'cat-body');
    body.id = bodyId;
    attr(body, 'role', 'region');
    attr(body, 'aria-labelledby', uid + '-h3');
    togBtn.id = uid + '-h3';           /* makes aria-labelledby resolve to button text */

    buildRows(body);
    sec.appendChild(body);

    togBtn.addEventListener('click', function () {
      var open = togBtn.getAttribute('aria-expanded') === 'true';
      attr(togBtn, 'aria-expanded', String(!open));
      body.classList.toggle('cat-collapsed', open);
      togIcon.textContent = open ? '\u25B8' : '\u25BE';
    });

    return sec;
  }

  /* ================================================================
     BUILD SECTION PANELS
  ================================================================ */
  function buildSections() {
    var main = document.getElementById('main');

    SECS.forEach(function (s, idx) {
      var qs    = SQ[s.id];
      var critN = qs.filter(function (q) { return q.imp === 'Critical Importance'; }).length;
      var isConditional = !!SECTION_GATES[s.id];

      var panel = mk('section', 'panel' + (idx === 0 ? ' active' : ''));
      panel.id = 'panel-' + s.id;
      attr(panel, 'aria-labelledby', 'sh-' + s.id);
      attr(panel, 'role', 'region');
      if (idx > 0) attr(panel, 'aria-hidden', 'true');

      /* Header — section title stays H2 */
      var hdr = mk('div', 'sec-hdr');
      var h2  = mk('h2'); h2.id = 'sh-' + s.id; h2.textContent = s.lbl; hdr.appendChild(h2);
      var desc = mk('p'); desc.textContent = s.desc; hdr.appendChild(desc);
      var chips = mk('div', 'chips');
      chips.appendChild(el_chip(qs.length + ' questions', ''));
      if (critN) chips.appendChild(el_chip('\u2605 ' + critN + ' critical', 'gold'));
      if (isConditional) chips.appendChild(el_chip('Conditionally required', 'grey'));
      hdr.appendChild(chips);
      panel.appendChild(hdr);

      /* Body */
      var body = mk('div', 'sec-body');

      /* Gate banner */
      if (isConditional) {
        var gate = SECTION_GATES[s.id];
        var banner = mk('div', 'gate-banner');
        banner.id = 'gate-banner-' + s.id;
        attr(banner, 'role', 'status');
        attr(banner, 'aria-live', 'polite');
        var gIcon = mk('span', 'gate-icon'); attr(gIcon, 'aria-hidden', 'true'); gIcon.textContent = '\u26a0';
        banner.appendChild(gIcon);
        var gText = mk('div');
        var gStrong = mk('strong'); gStrong.textContent = 'Section not required'; gText.appendChild(gStrong);
        gText.appendChild(txt('Based on your answer to ' + gate.label + ', this section does not need to be completed. Questions are shown for reference.'));
        banner.appendChild(gText);
        body.appendChild(banner);
      }

      /* Group questions by category — each group is a collapsible H3 */
      var cats = {};
      var catOrder = [];
      qs.forEach(function (q) {
        var c = q.id.slice(0, 4);
        if (!cats[c]) { cats[c] = []; catOrder.push(c); }
        cats[c].push(q);
      });

      catOrder.forEach(function (cat) {
        var catQs = cats[cat];
        var uid   = 'sec-' + s.id + '-' + cat;
        body.appendChild(mkCollapsible(CAT[cat] || cat, catQs.length, function (b) {
          catQs.forEach(function (q) { b.appendChild(buildQ(q, s.id)); });
        }, uid));
      });

      /* Footer nav */
      var foot = mk('div', 'sec-foot');
      var prog = mk('div', 'sec-prog');
      var sp = mk('span'); sp.id = 'sp-' + s.id; attr(sp, 'aria-live', 'polite');
      sp.textContent = '0/' + qs.length;
      var pw = mk('div', 'pw'); attr(pw, 'aria-hidden', 'true');
      var pf = mk('div', 'pf'); pf.id = 'pf-' + s.id;
      pw.appendChild(pf); prog.appendChild(sp); prog.appendChild(pw); foot.appendChild(prog);

      var fb = mk('div', 'foot-btns');
      if (idx > 0) {
        var pb = mk('button', 'fbn fbn-o fbn-sm'); pb.type = 'button';
        attr(pb, 'data-goto', SECS[idx - 1].id);
        attr(pb, 'aria-label', 'Go to previous section: ' + SECS[idx - 1].lbl);
        pb.textContent = '\u2190 ' + SECS[idx - 1].lbl;
        fb.appendChild(pb);
      }
      if (idx < SECS.length - 1) {
        var nb2 = mk('button', 'fbn fbn-p fbn-sm'); nb2.type = 'button';
        attr(nb2, 'data-goto', SECS[idx + 1].id);
        attr(nb2, 'aria-label', 'Go to next section: ' + SECS[idx + 1].lbl);
        nb2.textContent = 'Next: ' + SECS[idx + 1].lbl + ' \u2192';
        fb.appendChild(nb2);
      } else {
        var gb = mk('button', 'fbn fbn-g fbn-sm'); gb.type = 'button';
        attr(gb, 'data-goto', 'summary');
        attr(gb, 'aria-label', 'View assessment summary');
        gb.textContent = 'View Summary \u2192';
        fb.appendChild(gb);
      }
      foot.appendChild(fb);
      body.appendChild(foot);
      panel.appendChild(body);
      main.appendChild(panel);
    });

    /* Summary panel */
    var sp2 = mk('section', 'panel'); sp2.id = 'panel-summary';
    attr(sp2, 'aria-labelledby', 'sum-h'); attr(sp2, 'role', 'region'); attr(sp2, 'aria-hidden', 'true');
    var sh = mk('div', 'sec-hdr');
    var sh2 = mk('h2'); sh2.id = 'sum-h'; sh2.textContent = 'Assessment Summary'; sh.appendChild(sh2);
    var sd = mk('p'); sd.textContent = 'Full scoring overview for all HECVAT sections'; sh.appendChild(sd);
    sp2.appendChild(sh);
    var sb2 = mk('div', 'sec-body');
    var sgEl = mk('div', 'sgrid'); sgEl.id = 'sum-cards'; sb2.appendChild(sgEl);
    var ssEl = mk('div', 'ssecs'); ssEl.id = 'sum-secs'; sb2.appendChild(ssEl);
    var er = mk('div', 'exp-row');
    [['Export JSON', 'btn-nv', 'btn-exp2'], ['Export CSV', 'btn-ol', 'btn-csv2'], ['Print', 'btn-ol', 'btn-prt2']].forEach(function (inf) {
      var b = mk('button', 'btn ' + inf[1]); b.type = 'button'; b.id = inf[2]; b.textContent = inf[0]; er.appendChild(b);
    });
    var cp = mk('span', 'exp-copy');
    cp.textContent = 'HECVAT 4.1.5 \u2014 EDUCAUSE \u00a9 2025';
    er.appendChild(cp); sb2.appendChild(er); sp2.appendChild(sb2); main.appendChild(sp2);
  }

  function el_chip(label, mod) {
    var c = mk('span', 'chip' + (mod ? ' ' + mod : '')); c.textContent = label; return c;
  }

  /* ================================================================
     NAVIGATION
  ================================================================ */
  function goTo(id) {
    document.querySelectorAll('.panel').forEach(function (p) {
      p.classList.remove('active'); attr(p, 'aria-hidden', 'true');
    });
    document.querySelectorAll('.nb').forEach(function (b) {
      b.classList.remove('active'); attr(b, 'aria-current', 'false');
    });
    var panel = document.getElementById('panel-' + id);
    var nb    = document.getElementById('nb-' + id);
    if (panel) { panel.classList.add('active'); panel.removeAttribute('aria-hidden'); panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    if (nb)    { nb.classList.add('active'); attr(nb, 'aria-current', 'true'); }
    if (id === 'summary') renderSummary();
    /* Refresh eval scorecard when navigating to an eval tab */
    if (typeof EVAL_SECS !== 'undefined' && EVAL_SECS.some(function(es){ return es.id === id; })) {
      refreshEvalScorecard(id);
      refreshNNSummary();
    }
  }

  /* ================================================================
     ANSWER SELECTION
  ================================================================ */
  function pickAnswer(qid, val) {
    R[qid] = R[qid] || {};
    R[qid].value = val;

    var q = HECVAT_QUESTIONS.find(function (x) { return x.id === qid; });
    if (!q) return;

    /* Update button states.  Button element IDs use the full word
       ('yn-yes-*', 'yn-no-*', 'yn-na-*') but the visual selected-state
       classes use single letters ('sel-y', 'sel-n', 'sel-na') — map
       between the two explicitly. */
    var btnY  = document.getElementById('yn-yes-' + qid);
    var btnN  = document.getElementById('yn-no-'  + qid);
    var btnNA = document.getElementById('yn-na-'  + qid);
    [btnY, btnN, btnNA].forEach(function (b) {
      if (!b) return;
      attr(b, 'aria-pressed', 'false');
      b.classList.remove('sel-y', 'sel-n', 'sel-na');
    });
    if (val === 'Yes' && btnY)  { btnY.classList.add('sel-y');   attr(btnY,  'aria-pressed', 'true'); }
    else if (val === 'No' && btnN)  { btnN.classList.add('sel-n');   attr(btnN,  'aria-pressed', 'true'); }
    else if (val === 'N/A' && btnNA){ btnNA.classList.add('sel-na'); attr(btnNA, 'aria-pressed', 'true'); }

    /* Conditional guidance — show/hide with aria-hidden for screen readers */
    var yg = document.getElementById('yg-' + qid);
    var ng = document.getElementById('ng-' + qid);
    if (yg) { yg.classList.toggle('on', val === 'Yes'); attr(yg, 'aria-hidden', val === 'Yes' ? 'false' : 'true'); }
    if (ng) { ng.classList.toggle('on', val === 'No');  attr(ng, 'aria-hidden', val === 'No'  ? 'false' : 'true'); }

    /* Compliance indicator — only show when q.comp is a scorable Yes/No.
       Questions with comp='Not scored' (or unset, or loc='Not Scored', or
       score='NA') are routing/informational questions and must never display
       a Compliant / Non-compliant verdict. */
    var ci = document.getElementById('ci-' + qid);
    if (ci) {
      var scorable = (q.comp === 'Yes' || q.comp === 'No') &&
                     q.loc !== 'Not Scored' && q.score !== 'NA';
      ci.className = 'cind';
      ci.textContent = '';
      if (!scorable) {
        /* Leave indicator hidden for routing / not-scored questions */
      } else if (val === 'N/A') {
        ci.className = 'cind on neu';
        ci.textContent = '\u2014 N/A \u2014 Not applicable';
      } else if (val === q.comp) {
        ci.className = 'cind on ok';
        ci.textContent = '\u2713 Compliant response';
      } else {
        ci.className = 'cind on bad';
        ci.textContent = '\u2717 Non-compliant response';
      }
    }

    /* Refresh cross-reference displays for this question */
    xrefRegistry.forEach(function (x) { if (x.qid === qid) syncXrefDisplay(x.el, qid); });

    /* Propagate to linked secondary instances */
    (secondaryReg[qid] || []).forEach(function (ii) {
      if (ii.isLinked()) ii.updateUI(val);
    });

    checkGates();
    refreshProgress();
  }

  /* Clear a Yes/No/N/A answer (deselect — same button clicked twice) */
  function clearAnswer(qid) {
    if (R[qid]) delete R[qid].value;

    var q = HECVAT_QUESTIONS.find(function(x){ return x.id === qid; });

    /* Reset all Yes/No/NA buttons (IDs use full-word suffixes) */
    ['yes','no','na'].forEach(function(v) {
      var btn = document.getElementById('yn-' + v + '-' + qid);
      if (!btn) return;
      attr(btn, 'aria-pressed', 'false');
      btn.classList.remove('sel-y','sel-n','sel-na');
    });

    /* Hide guidance and compliance indicator */
    var yg = document.getElementById('yg-' + qid);
    var ng = document.getElementById('ng-' + qid);
    var ci = document.getElementById('ci-' + qid);
    if (yg) { yg.classList.remove('on'); attr(yg, 'aria-hidden', 'true'); }
    if (ng) { ng.classList.remove('on'); attr(ng, 'aria-hidden', 'true'); }
    if (ci) { ci.className = 'cind'; ci.textContent = ''; }

    xrefRegistry.forEach(function(x){ if(x.qid===qid) syncXrefDisplay(x.el,qid); });

    /* Propagate clear to linked secondary instances */
    (secondaryReg[qid] || []).forEach(function (ii) {
      if (ii.isLinked()) ii.updateUI('');
    });

    checkGates();
    refreshProgress();
  }


  document.getElementById('main').addEventListener('input', function (e) {
    var qid  = e.target.getAttribute('data-qid');
    var nqid = e.target.getAttribute('data-notes-qid');
    if (qid) {
      R[qid] = R[qid] || {};
      R[qid].value = e.target.value;
      /* Update cross-references for text values */
      xrefRegistry.forEach(function (x) { if (x.qid === qid) syncXrefDisplay(x.el, qid); });
      /* Propagate to linked secondary instances */
      (secondaryReg[qid] || []).forEach(function (ii) {
        if (ii.isLinked()) ii.updateUI(e.target.value);
      });
      refreshProgress();
    }
    if (nqid) {
      R[nqid] = R[nqid] || {};
      R[nqid].notes = e.target.value;
      /* Propagate notes to linked secondary instances */
      (secondaryReg[nqid] || []).forEach(function (ii) {
        if (ii.isLinked()) ii.updateNotesUI(e.target.value);
      });
    }
  });

  document.getElementById('main').addEventListener('click', function (e) {
    /* Yes/No/N/A button — clicking the already-selected answer deselects it */
    var yn = e.target.closest('.ynb');
    if (yn && yn.getAttribute('data-qid') && yn.getAttribute('data-val')) {
      /* Secondary instances have their own per-button listeners (wired in
         buildQSecondary) — skip them here so we don't double-fire. */
      if (yn.getAttribute('data-sec')) return;
      var qidYn  = yn.getAttribute('data-qid');
      var valYn  = yn.getAttribute('data-val');
      var already = R[qidYn] && R[qidYn].value === valYn;
      if (already) {
        clearAnswer(qidYn);
      } else {
        pickAnswer(qidYn, valYn);
      }
      return;
    }
    /* Notes toggle */
    var nt = e.target.closest('[data-notes-for]');
    if (nt) {
      var qid2 = nt.getAttribute('data-notes-for');
      var area = document.getElementById('na-' + qid2);
      var open = nt.getAttribute('aria-expanded') === 'true';
      attr(nt, 'aria-expanded', String(!open));
      area.classList.toggle('on', !open);
      /* Update visible label and accessible label */
      var newLabel = open ? '+ Add notes' : '\u2212 Hide notes';
      nt.firstChild.textContent = newLabel;
      /* Update the aria-label prefix */
      var q3 = HECVAT_QUESTIONS.find(function (x) { return x.id === qid2; });
      if (q3) attr(nt, 'aria-label', (open ? 'Add' : 'Hide') + ' notes for ' + qid2 + ': ' + q3.q);
      return;
    }
    /* Section nav (footer buttons + cross-ref goto) */
    var gt = e.target.closest('[data-goto]');
    if (gt) { goTo(gt.getAttribute('data-goto')); return; }
    /* Summary panel buttons */
    var id = e.target.id;
    if (id === 'btn-exp2') exportJSON();
    else if (id === 'btn-csv2') exportCSV();
    else if (id === 'btn-prt2') window.print();
  });

  /* ================================================================
     SECTION GATING
  ================================================================ */
  function checkGates() {
    Object.keys(SECTION_GATES).forEach(function (sid) {
      var gate   = SECTION_GATES[sid];
      var val    = R[gate.reqId] && R[gate.reqId].value;
      var gated  = (val === 'No');

      var nb     = document.getElementById('nb-' + sid);
      var tag    = document.getElementById('nb-tag-' + sid);
      var banner = document.getElementById('gate-banner-' + sid);

      if (nb)     { nb.classList.toggle('dimmed', gated); nb.classList.toggle('not-req', gated); }
      if (tag)    { tag.classList.toggle('hidden', !gated); tag.className = 'nb-tag' + (gated ? ' nr' : ' hidden'); }
      if (banner) { banner.classList.toggle('visible', gated); }
    });
  }

  /* ================================================================
     SCORING
  ================================================================ */
  function calcScore() {
    var earned = 0, pot = 0, comp = 0, nc = 0, ci = 0, ss = {};
    SECS.forEach(function (s) {
      var se = 0, sp = 0;
      SQ[s.id].forEach(function (q) {
        /* Only score in primary section to avoid double-counting */
        if (renderedIn[q.id] !== s.id) return;
        if (q.score === 'NA' || q.loc === 'Not Scored') return;
        var p = pts(q.imp); sp += p;
        var v = R[q.id] && R[q.id].value;
        if (!v) return;
        if (v === 'N/A') { sp -= p; return; }
        var ok = q.comp ? v === q.comp : v === 'Yes';
        if (ok) { se += p; comp++; } else { nc++; if (q.imp === 'Critical Importance') ci++; }
      });
      earned += se; pot += sp; ss[s.id] = { e: se, p: sp };
    });
    return { earned: earned, pot: pot, comp: comp, nc: nc, ci: ci, ss: ss,
             pct: pot > 0 ? Math.round(earned / pot * 100) : 0 };
  }

  /* ================================================================
     PROGRESS + SCORE BANNER
  ================================================================ */
  function refreshProgress() {
    var sc = calcScore(), ans = 0, tot = 0;
    SECS.forEach(function (s) {
      /* Count only primary questions (cross-refs aren't answered here) */
      var primQs = SQ[s.id].filter(function (q) { return renderedIn[q.id] === s.id; });
      var a = primQs.filter(function (q) { return R[q.id] && R[q.id].value && R[q.id].value.length > 0; }).length;
      ans += a; tot += primQs.length;

      var pct = primQs.length > 0 ? Math.round(a / primQs.length * 100) : 0;
      var pf = document.getElementById('pf-' + s.id); if (pf) pf.style.width = pct + '%';
      var sp = document.getElementById('sp-' + s.id); if (sp) sp.textContent = a + '/' + primQs.length;
      var nc2 = document.getElementById('nc-' + s.id); if (nc2) nc2.textContent = a;
      var nb2 = document.getElementById('nb-' + s.id);
      if (nb2) nb2.classList.toggle('done', a === primQs.length && primQs.length > 0);
    });

    var of = document.getElementById('overall-fill');
    if (of) of.style.width = (tot > 0 ? Math.round(ans / tot * 100) : 0) + '%';

    document.getElementById('sb-s').textContent = sc.earned + '/' + sc.pot;
    var pb = document.getElementById('sb-p');
    pb.textContent = sc.pct + '%';
    pb.className = 'pct ' + (sc.pct >= 80 ? 'g' : sc.pct >= 60 ? 'o' : 'r');
    document.getElementById('sb-a').textContent  = ans;
    document.getElementById('sb-t').textContent  = tot;
    document.getElementById('sb-c').textContent  = sc.comp;
    document.getElementById('sb-nc').textContent = sc.nc;
    document.getElementById('sb-ci').textContent = sc.ci;

    refreshXrefs();
    refreshEvalDisplays();
  }

  /* ================================================================
     SUMMARY RENDER
  ================================================================ */
  function renderSummary() {
    var sc = calcScore(), ans = 0, tot = 0;
    SECS.forEach(function (s) {
      var primQs = SQ[s.id].filter(function (q) { return renderedIn[q.id] === s.id; });
      ans += primQs.filter(function (q) { return R[q.id] && R[q.id].value && R[q.id].value.length > 0; }).length;
      tot += primQs.length;
    });

    var cards = document.getElementById('sum-cards'); cards.replaceChildren();
    [
      [sc.pct + '%', 'Overall Score',   sc.pct >= 80 ? 'col-green' : sc.pct >= 60 ? 'col-amber' : 'col-red'],
      [sc.earned,    'Points Earned',   null],
      [sc.pot,       'Points Possible', null],
      [sc.comp,      'Compliant',       'col-green'],
      [sc.nc,        'Non-Compliant',   'col-red'],
      [sc.ci,        'Critical Issues', sc.ci > 0 ? 'col-red' : 'col-green'],
      [ans,          'Answered',        null],
      [tot - ans,    'Remaining',       'col-muted'],
    ].forEach(function (d) {
      var card = mk('div', 'sc');
      var big  = mk('div', 'sc-big' + (d[2] ? ' ' + d[2] : '')); big.textContent = String(d[0]);
      var lbl  = mk('div', 'sc-lbl'); lbl.textContent = d[1];
      card.appendChild(big); card.appendChild(lbl); cards.appendChild(card);
    });

    var secs = document.getElementById('sum-secs'); secs.replaceChildren();
    SECS.forEach(function (s) {
      var d = sc.ss[s.id] || { e: 0, p: 0 };
      var primQs = SQ[s.id].filter(function (q) { return renderedIn[q.id] === s.id; });
      var a   = primQs.filter(function (q) { return R[q.id] && R[q.id].value && R[q.id].value.length > 0; }).length;
      var pct = d.p > 0 ? Math.round(d.e / d.p * 100) : null;
      var bc  = pct === null ? '' : pct >= 80 ? 'g' : pct >= 60 ? 'o' : 'r';
      var isGated = (function () { var g = SECTION_GATES[s.id]; return g && R[g.reqId] && R[g.reqId].value === 'No'; })();

      var card = mk('div', 'ssc' + (isGated ? ' ssc-gated' : ''));
      var n = mk('div', 'ssc-n'); n.textContent = s.lbl + (isGated ? ' (Not Required)' : ''); card.appendChild(n);
      var bw = mk('div', 'ssc-bw'); attr(bw, 'aria-hidden', 'true');
      var bf = mk('div', 'ssc-bf ' + bc); bf.style.width = (pct || 0) + '%';
      bw.appendChild(bf); card.appendChild(bw);
      var nm = mk('div', 'ssc-nm');
      var lft = mk('span'); lft.textContent = (pct !== null ? pct + '%' : 'N/A') + ' \u2014 ' + d.e + '/' + d.p + ' pts';
      var rgt = mk('span', 'col-muted'); rgt.textContent = a + '/' + primQs.length + ' primary';
      nm.appendChild(lft); nm.appendChild(rgt); card.appendChild(nm); secs.appendChild(card);
    });
  }

  /* ================================================================
     SAVE / LOAD / RESTORE / CLEAR
  ================================================================ */

  var storageStatus = document.getElementById('storage-status');
  function setStatus(msg, state) {
    if (!storageStatus) return;
    /* state: 'ok' | 'warn' | 'error' | '' — drives CSS class, not inline style */
    storageStatus.textContent = msg;
    storageStatus.className = 'storage-status' + (state ? ' status-' + state : '');
    if (msg) setTimeout(function () {
      storageStatus.textContent = '';
      storageStatus.className = 'storage-status';
    }, 6000);
  }

  function saveData() {
    setStatus('Saving\u2026', 'pending');
    HECVAT_SEC.saveEncrypted(R).then(function () {
      setStatus('Saved \u2014 AES-256-GCM encrypted', 'ok');
    }).catch(function (e) {
      setStatus('Save failed: ' + e.message, 'error');
    });
  }

  function loadData() {
    setStatus('Loading\u2026', 'pending');
    HECVAT_SEC.loadDecrypted().then(function (raw) {
      if (!raw) { setStatus('No saved data found.', ''); return; }

      /* Validate every record before accepting it */
      var clean = {};
      var dropped = 0;
      Object.keys(raw).forEach(function (qid) {
        var rec = HECVAT_SEC.validateRecord(qid, raw[qid]);
        if (rec) { clean[qid] = rec; } else { dropped++; }
      });

      R = clean;
      restoreUI();
      refreshProgress();
      checkGates();

      var msg = 'Progress loaded' + (dropped ? ' (' + dropped + ' invalid record(s) discarded)' : '') + '.';
      setStatus(msg, dropped ? 'warn' : 'ok');
    }).catch(function (e) {
      setStatus('Load failed: ' + e.message, 'error');
    });
  }

  function clearData() {
    var confirmed = window.confirm(
      'This will permanently delete all saved progress from this browser.\n\n' +
      'Export your responses first if you need them.\n\nContinue?'
    );
    if (!confirmed) return;
    HECVAT_SEC.clearAll();
    /* Reset in-memory state and reload for a clean slate */
    window.location.reload();
  }

  function restoreUI() {
    Object.keys(R).forEach(function (qid) {
      var resp = R[qid];
      var q    = HECVAT_QUESTIONS.find(function (x) { return x.id === qid; }); if (!q) return;
      if (resp.value !== undefined) {
        if (q.type === 'text' || q.type === 'textarea' || q.type === 'select') {
          var elInp = document.getElementById('fi-' + qid);
          /* Write via value property — never innerHTML */
          if (elInp) elInp.value = resp.value;
          /* Update linked secondary instances */
          (secondaryReg[qid] || []).forEach(function (ii) {
            if (ii.isLinked()) ii.updateUI(resp.value);
          });
        } else { pickAnswer(qid, resp.value); }
      }
      if (resp.notes) {
        var ni = document.getElementById('ni-' + qid);
        /* Write via value property — never innerHTML */
        if (ni) {
          ni.value = resp.notes;
          var noteArea = document.getElementById('na-' + qid);
          if (noteArea) noteArea.classList.add('on');
        }
        (secondaryReg[qid] || []).forEach(function (ii) {
          if (ii.isLinked()) ii.updateNotesUI(resp.notes);
        });
      }
    });
  }

  /* ================================================================
     EXPORT
     NOTE: Exported files are plaintext. Handle them as sensitive
     documents — store securely, transmit encrypted (e.g. TLS),
     and delete when no longer needed.
  ================================================================ */
  function dl(content, type, name) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type: type }));
    a.download = name; document.body.appendChild(a); a.click();
    /* Revoke object URL immediately after click */
    setTimeout(function () { URL.revokeObjectURL(a.href); document.body.removeChild(a); }, 100);
  }

  function exportJSON() {
    var data = {
      meta: {
        tool: 'HECVAT', version: '4.1.5',
        exported: new Date().toISOString(),
        notice: 'This file contains sensitive assessment data. Handle as confidential, transmit only over encrypted channels, and delete when no longer required.'
      },
      score: calcScore(),
      responses: {}
    };
    HECVAT_QUESTIONS.forEach(function (q) {
      if (R[q.id]) data.responses[q.id] = {
        question: q.q, value: R[q.id].value || '',
        notes: R[q.id].notes || '', importance: q.imp,
        primarySection: renderedIn[q.id] || q.sections[0]
      };
    });
    dl(JSON.stringify(data, null, 2), 'application/json', 'HECVAT-415-responses.json');
    setStatus('JSON exported \u2014 handle as confidential', 'warn');
  }

  function exportCSV() {
    /* CSV formula injection defence: if a cell value starts with
       = + - @ or a tab/CR, prefix with a single quote so spreadsheet
       apps treat it as text rather than a formula.  The quote is
       visible in the raw file but stripped by compliant parsers when
       they display the cell.  Per OWASP CSV injection guidance. */
    function safeCsvCell(v) {
      var s = String(v == null ? '' : v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    }

    var rows = [['ID', 'Question', 'Primary Section', 'Importance', 'Response', 'Notes', 'Compliant Response', 'Score Mapping']];
    HECVAT_QUESTIONS.forEach(function (q) {
      var r = R[q.id] || {};
      rows.push([q.id, q.q, renderedIn[q.id] || q.sections[0], q.imp, r.value || '', r.notes || '', q.comp || '', q.score || '']);
    });
    dl(rows.map(function (r) {
      return r.map(safeCsvCell).join(',');
    }).join('\n'), 'text/csv', 'HECVAT-415-responses.csv');
    setStatus('CSV exported \u2014 handle as confidential', 'warn');
  }

  /* ================================================================
     FILE PICKER HELPER
     Creates a temporary <input type="file"> appended to document.body,
     clicks it, then removes it after use.
     This is the most cross-browser reliable approach:
       - Appended to body, so no parent overflow:hidden clips it
       - Created synchronously inside the user-gesture handler, so
         the browser permits .click() without a trusted-event check
       - Cleaned up immediately after the user picks (or cancels)
  ================================================================ */
  function openFilePicker(accept, onFile) {
    var input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    /* Position off-screen — visible to the render tree but not to the user */
    input.style.cssText = 'position:fixed;top:-200px;left:-200px;width:1px;height:1px;opacity:0;';
    document.body.appendChild(input);

    /* 'change' fires when a file is picked */
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      document.body.removeChild(input);
      if (file) onFile(file);
    });

    /* 'cancel' fires in Chrome 113+ / Firefox 113+ when the picker is dismissed */
    input.addEventListener('cancel', function () {
      document.body.removeChild(input);
    });

    input.click();
  }

  /* ================================================================
     IMPORT — JSON
  ================================================================ */
  function importJSON() {
    openFilePicker('.json,application/json', handleJSONImport);
  }

  function handleJSONImport(file) {
    setStatus('Reading ' + HECVAT_SEC.sanitize(file.name) + '\u2026', 'pending');
    var reader = new FileReader();
    reader.onerror = function () { setStatus('Could not read file.', 'error'); };
    reader.onload = function (ev) {
      var parsed;
      try { parsed = JSON.parse(ev.target.result); }
      catch (err) { setStatus('File is not valid JSON: ' + err.message, 'error'); return; }
      /* Accept full export format { meta, responses:{...} } or bare { qid:{value,notes} } */
      var raw = (parsed && typeof parsed.responses === 'object') ? parsed.responses : parsed;
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        setStatus('JSON structure not recognised. Expected a HECVAT export file.', 'error'); return;
      }
      applyImport(raw, file.name);
    };
    reader.readAsText(file);
  }

  /* ================================================================
     IMPORT — CSV
  ================================================================ */
  function importCSV() {
    openFilePicker('.csv,text/csv', handleCSVImport);
  }

  function handleCSVImport(file) {
    setStatus('Reading ' + HECVAT_SEC.sanitize(file.name) + '\u2026', 'pending');
    var reader = new FileReader();
    reader.onerror = function () { setStatus('Could not read file.', 'error'); };
    reader.onload = function (ev) {
      var raw;
      try { raw = parseCSVToMap(ev.target.result); }
      catch (err) { setStatus('CSV error: ' + err.message, 'error'); return; }
      applyImport(raw, file.name);
    };
    reader.readAsText(file);
  }

  /* RFC-4180 compliant CSV parser — handles multiline quoted fields,
     escaped double-quotes, and mixed line endings.
     Returns { qid: { value, notes } } map.
     Expected columns (from exportCSV):
       0=ID  1=Question  2=PrimarySection  3=Importance
       4=Response  5=Notes  6=CompliantResponse  7=ScoreMapping  */
  function parseCSVToMap(text) {
    /* Normalise line endings but preserve newlines inside quoted fields */
    var src = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    /* Tokenise the entire document character-by-character (RFC-4180) */
    function tokenise(s) {
      var rows = [], row = [], cell = '', i = 0, len = s.length;
      while (i < len) {
        var c = s[i];
        if (c === '"') {
          /* Quoted field */
          i++;
          while (i < len) {
            if (s[i] === '"') {
              if (s[i + 1] === '"') { cell += '"'; i += 2; }  /* escaped quote */
              else { i++; break; }                             /* end of field */
            } else { cell += s[i++]; }
          }
        } else if (c === ',') {
          row.push(cell); cell = ''; i++;
        } else if (c === '\n') {
          row.push(cell); rows.push(row); row = []; cell = ''; i++;
        } else {
          cell += c; i++;
        }
      }
      if (cell || row.length) { row.push(cell); rows.push(row); }
      return rows;
    }

    var rows = tokenise(src);
    if (rows.length < 2) throw new Error('File appears to be empty.');

    var headers = rows[0].map(function(h){ return h.trim().toLowerCase(); });
    var idCol    = headers.indexOf('id');
    var valCol   = headers.indexOf('response');
    var notesCol = headers.indexOf('notes');

    if (idCol === -1 || valCol === -1) {
      throw new Error('Required columns "ID" and "Response" not found. Ensure this is a HECVAT CSV export.');
    }

    var map = {};
    for (var li = 1; li < rows.length; li++) {
      var cells = rows[li];
      var qid   = (cells[idCol] || '').trim();
      if (!qid) continue;
      var entry = {};

      /* Strip the formula-injection prefix quote added on export */
      var val = (cells[valCol] || '').trim();
      if (val.charAt(0) === "'" && val.length > 1) val = val.slice(1);
      if (val) entry.value = val;

      if (notesCol > -1) {
        var notes = (cells[notesCol] || '').trim();
        if (notes.charAt(0) === "'" && notes.length > 1) notes = notes.slice(1);
        if (notes) entry.notes = notes;
      }

      if (entry.value !== undefined || entry.notes !== undefined) map[qid] = entry;
    }
    if (Object.keys(map).length === 0) throw new Error('No response data found in CSV.');
    return map;
  }

  /* ================================================================
     IMPORT — HECVAT EXCEL (.xlsx)
     - File size capped at MAX_XLSX_MB to block zip bombs
     - Parsing runs inside a Web Worker (hecvat-worker.js) so a
       malformed/malicious file cannot crash or exploit the main UI
  ================================================================ */
  var MAX_XLSX_MB   = 20;
  var MAX_XLSX_BYTES = MAX_XLSX_MB * 1024 * 1024;

  function importXLSX() {
    openFilePicker('.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', handleXLSXImport);
  }

  function handleXLSXImport(file) {
    if (!file) return;

    /* ── File size guard ── */
    if (file.size > MAX_XLSX_BYTES) {
      setStatus('File too large (' + (file.size / 1048576).toFixed(1) + ' MB). Maximum is ' + MAX_XLSX_MB + ' MB.', 'error');
      return;
    }

    setStatus('Parsing ' + HECVAT_SEC.sanitize(file.name) + '\u2026', 'pending');

    var reader = new FileReader();
    reader.onerror = function () { setStatus('Could not read file.', 'error'); };
    reader.onload  = function (ev) {
      /* ── Spin up a Worker for isolated parsing ── */
      var worker;
      try {
        worker = new Worker('hecvat-worker.js');
      } catch (e) {
        /* Worker unavailable (e.g. file:// with restrictive browser settings) —
           fall back to main-thread parsing with the bundled SheetJS             */
        if (typeof XLSX === 'undefined') {
          setStatus('XLSX parser unavailable — refresh and try again.', 'error');
          return;
        }
        try {
          var wb  = XLSX.read(ev.target.result, { type:'array', cellFormula:false, cellHTML:false });
          var raw = parseXLSXResponses(wb);
          applyImport(raw, file.name);
        } catch (err) { setStatus('XLSX error: ' + err.message, 'error'); }
        return;
      }

      var timeout = setTimeout(function () {
        worker.terminate();
        setStatus('XLSX parsing timed out — the file may be corrupt.', 'error');
      }, 30000);

      worker.onmessage = function (msg) {
        clearTimeout(timeout);
        worker.terminate();
        if (msg.data.success) {
          applyImport(msg.data.data, file.name);
        } else {
          setStatus(msg.data.error, 'error');
        }
      };

      worker.onerror = function (err) {
        clearTimeout(timeout);
        worker.terminate();
        setStatus('Worker error: ' + (err.message || 'unknown'), 'error');
      };

      /* Transfer the ArrayBuffer to the worker (zero-copy) */
      var buf = ev.target.result;
      worker.postMessage(buf, [buf]);
    };

    reader.readAsArrayBuffer(file);
  }

  /* Main-thread fallback parser (mirrors hecvat-worker.js logic) */
  function parseXLSXResponses(workbook) {
    var SHEET_CATS = {
      'START HERE':       ['GNRL','COMP','REQU'],
      'Organization':     ['DOCU','THRD','PPPR','CHNG','CONS'],
      'Product':          ['APPL','AAAI','DATA'],
      'Infrastructure':   ['DCTR','FIDP','HFIH','VULN'],
      'IT Accessibility': ['ITAC'],
      'Case-Specific':    ['HIPA','PCID','OPEM'],
      'AI':               ['AIQU','AIGN','AIPL','AISC','AIML','AILM'],
      'Privacy':          ['PRGN','PCOM','PDOC','PTHP','PCHG','PDAT','PRPO','INTL','DRPV','DPAI'],
    };
    var catToSheet = {};
    Object.keys(SHEET_CATS).forEach(function(s){ SHEET_CATS[s].forEach(function(c){ catToSheet[c]=s; }); });
    var QID_RE = /^[A-Z]{2,5}-\d{1,3}$/;
    var map = {};
    Object.keys(SHEET_CATS).forEach(function(sheetName) {
      var ws = workbook.Sheets[sheetName]; if (!ws) return;
      var data = XLSX.utils.sheet_to_json(ws,{header:1,defval:null,blankrows:false,raw:false});
      data.forEach(function(row) {
        var qid = row[0] ? String(row[0]).trim() : '';
        if (!QID_RE.test(qid)) return;
        if (catToSheet[qid.slice(0,4)] !== sheetName) return;
        var val = row[2] != null ? String(row[2]).trim() : '';
        var notes = row[3] != null ? String(row[3]).trim() : '';
        if (val.charAt(0)==='=') return;
        if (/^yes$/i.test(val)) val='Yes'; else if (/^no$/i.test(val)) val='No';
        else if (/^n\/a$/i.test(val)||/^na$/i.test(val)) val='N/A';
        if (val||notes){ var e={}; if(val) e.value=val; if(notes) e.notes=notes; map[qid]=e; }
      });
    });
    if (!Object.keys(map).length) throw new Error('No answers found in this file.');
    return map;
  }
  function applyImport(raw, fileName) {
    var clean = {}, accepted = 0, dropped = 0;
    Object.keys(raw).forEach(function (qid) {
      var rec = HECVAT_SEC.validateRecord(qid, raw[qid]);
      if (rec) { clean[qid] = rec; accepted++; } else { dropped++; }
    });

    if (accepted === 0) {
      setStatus('No valid responses found in ' + HECVAT_SEC.sanitize(fileName) + '.', 'error');
      return;
    }

    /* Warn before overwriting existing answers */
    var existing = Object.keys(R).filter(function (k) { return R[k] && R[k].value; }).length;
    if (existing > 0) {
      var ok = window.confirm(
        'You have ' + existing + ' existing answer(s).\n\n' +
        'Importing will merge the file with your current answers.\n' +
        'Imported values overwrite any conflicting existing answers.\n\nContinue?'
      );
      if (!ok) { setStatus('Import cancelled.', ''); return; }
    }

    /* Merge: imported values win on conflict */
    Object.keys(clean).forEach(function (qid) {
      R[qid] = R[qid] || {};
      if (clean[qid].value !== undefined) R[qid].value = clean[qid].value;
      if (clean[qid].notes !== undefined) R[qid].notes = clean[qid].notes;
    });

    restoreUI();
    refreshProgress();
    checkGates();

    var msg = 'Imported ' + accepted + ' response(s) from ' + HECVAT_SEC.sanitize(fileName)
              + (dropped ? ' \u2014 ' + dropped + ' invalid record(s) skipped.' : '.');
    setStatus(msg, dropped ? 'warn' : 'ok');
  }

  /* ================================================================
     EXPORT — HECVAT EXCEL (.xlsx)
     Produces a workbook with 8 vendor response sheets + Score Summary,
     matching the official HECVAT column layout so recipients can
     open it alongside the official spreadsheet with columns aligned:
       A = Question ID  |  B = Question text  |  C = Answer
       D = Notes        |  E = Compliance     |  F = Importance
  ================================================================ */
  function exportXLSX() {
    if (typeof XLSX === 'undefined') {
      setStatus('XLSX library not loaded \u2014 refresh and try again.', 'error');
      return;
    }

    var VENDOR_SHEETS = [
      { name: 'START HERE',       cats: ['GNRL','COMP','REQU'] },
      { name: 'Organization',     cats: ['DOCU','THRD','PPPR','CHNG','CONS'] },
      { name: 'Product',          cats: ['APPL','AAAI','DATA'] },
      { name: 'Infrastructure',   cats: ['DCTR','FIDP','HFIH','VULN'] },
      { name: 'IT Accessibility', cats: ['ITAC'] },
      { name: 'Case-Specific',    cats: ['HIPA','PCID','OPEM'] },
      { name: 'AI',               cats: ['AIQU','AIGN','AIPL','AISC','AIML','AILM'] },
      { name: 'Privacy',          cats: ['PRGN','PCOM','PDOC','PTHP','PCHG','PDAT','PRPO','INTL','DRPV','DPAI'] },
    ];
    var sectionNameMap = {
      'start':'START HERE','org':'Organization','product':'Product',
      'infra':'Infrastructure','access':'IT Accessibility',
      'case':'Case-Specific','ai':'AI','privacy':'Privacy',
    };

    var wb = XLSX.utils.book_new();

    /* ── Score Summary sheet ── */
    var summaryRows = [
      ['HECVAT 4.1.5 \u2014 Score Summary'],
      ['Generated', new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})],
      ['Notice','Exported from the HECVAT 4.1.5 Web Form. Unofficial implementation \u2014 not affiliated with EDUCAUSE.'],
      [],
      ['Score Location','Earned (pts)','Possible (pts)','Score %','Questions'],
    ];
    var scoreGroups = {};
    HECVAT_QUESTIONS.forEach(function(q) {
      if (q.loc === 'Not Scored' || q.score === 'NA') return;
      (scoreGroups[q.loc] = scoreGroups[q.loc] || []).push(q);
    });
    var totalE = 0, totalP = 0;
    Object.keys(scoreGroups).sort().forEach(function(loc) {
      var qs = scoreGroups[loc], earned = 0, pot = 0;
      qs.forEach(function(q) {
        var p = q.imp === 'Critical Importance' ? 20 : q.imp === 'Standard Importance' ? 10 : q.imp === 'Minor Importance' ? 5 : 0;
        if (!p) return; pot += p;
        var v = R[q.id] && R[q.id].value;
        if (!v) return; if (v === 'N/A') { pot -= p; return; }
        if (q.comp ? v === q.comp : v === 'Yes') earned += p;
      });
      totalE += earned; totalP += pot;
      summaryRows.push([loc, earned, pot, pot > 0 ? Math.round(earned/pot*100)+'%' : 'N/A', qs.length]);
    });
    summaryRows.push([], ['OVERALL SCORE', totalE, totalP, totalP > 0 ? Math.round(totalE/totalP*100)+'%' : 'N/A', '']);
    var wsSumm = XLSX.utils.aoa_to_sheet(summaryRows);
    wsSumm['!cols'] = [{wch:28},{wch:14},{wch:14},{wch:10},{wch:10}];
    XLSX.utils.book_append_sheet(wb, wsSumm, 'Score Summary');

    /* ── Vendor response sheets ── */
    VENDOR_SHEETS.forEach(function(def) {
      var rows = [
        ['HECVAT 4.1.5 \u2014 ' + def.name,
         'Exported: ' + new Date().toLocaleDateString(),
         'UNOFFICIAL \u2014 Not affiliated with EDUCAUSE', '', '', ''],
        ['Question ID','Question','Answer','Notes / Additional Information','Compliance','Importance'],
      ];

      HECVAT_QUESTIONS.forEach(function(q) {
        /* Determine if this question belongs in this sheet */
        var cat = q.id.slice(0,4);
        var isPrimary  = def.cats.indexOf(cat) > -1;
        var isCrossRef = !isPrimary && q.sections.some(function(s){ return sectionNameMap[s] === def.name; });
        if (!isPrimary && !isCrossRef) return;

        var resp = R[q.id] || {};
        var val  = resp.value || '';
        var notes = resp.notes || '';
        if (isCrossRef && val) notes = (notes ? notes + ' ' : '') + '[See primary section for ' + q.id + ']';

        var compStr = '';
        if (val === 'N/A') { compStr = 'N/A'; }
        else if (val) { compStr = (q.comp ? val === q.comp : val === 'Yes') ? 'Compliant' : 'Non-Compliant'; }

        rows.push([q.id, q.q, val, notes, compStr, q.imp || '']);
      });

      var ws = XLSX.utils.aoa_to_sheet(rows);
      ws['!cols'] = [{wch:12},{wch:65},{wch:12},{wch:45},{wch:16},{wch:22}];
      ws['!freeze'] = { xSplit: 0, ySplit: 2 };
      XLSX.utils.book_append_sheet(wb, ws, def.name);
    });

    /* Trigger download */
    var today = new Date().toISOString().slice(0,10);
    var fname = 'HECVAT-415-Responses-' + today + '.xlsx';
    try {
      XLSX.writeFile(wb, fname);
    } catch (e) {
      var buf  = XLSX.write(wb, { bookType:'xlsx', type:'array' });
      var blob = new Blob([buf], { type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      a.href = url; a.download = fname;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(function(){ URL.revokeObjectURL(url); }, 60000);
    }
    setStatus('Excel exported \u2014 handle as confidential.', 'warn');
  }

  /* ================================================================
     WIRE SIDEBAR BUTTONS
  ================================================================ */
  function wireSidebarButtons() {
    document.getElementById('btn-sum').addEventListener('click',  function () { goTo('summary'); });
    document.getElementById('btn-save').addEventListener('click', saveData);
    document.getElementById('btn-load').addEventListener('click', loadData);
    document.getElementById('btn-exp').addEventListener('click',      exportJSON);
    document.getElementById('btn-csv').addEventListener('click',      exportCSV);
    document.getElementById('btn-exp-xlsx').addEventListener('click', exportXLSX);
    document.getElementById('btn-imp-json').addEventListener('click', importJSON);
    document.getElementById('btn-imp-csv').addEventListener('click',  importCSV);
    document.getElementById('btn-imp-xlsx').addEventListener('click', importXLSX);
    document.getElementById('btn-prt').addEventListener('click',  function () { window.print(); });
    document.getElementById('btn-clear').addEventListener('click', clearData);
  }

  /* ================================================================
     ANALYST EVALUATIONS
  ================================================================ */

  var EVAL_SECS = [
    { id: 'inst-eval',    lbl: 'Institution Evaluation', icon: '\uD83D\uDCCB',
      desc: 'Full analyst review — all sections with vendor responses and override fields' },
    { id: 'high-risk',   lbl: 'High-Risk Evaluation',   icon: '\u26A0',
      desc: 'Critical importance questions and non-negotiable flags' },
    { id: 'privacy-eval',lbl: 'Privacy Analyst Evaluation', icon: '\uD83D\uDD12',
      desc: 'Privacy-specific questions reviewed by privacy analyst' },
  ];

  var IMP_OPTS  = ['', 'Minor Importance', 'Standard Importance', 'Critical Importance'];
  var COMP_OPTS = ['', 'Mark as Compliant', 'Mark as Non-Compliant'];

  /* ================================================================
     EVALUATION DATA STRUCTURES (matching xlsx exactly)
  ================================================================ */

  /* Institution Evaluation Report Sections — category code order from spreadsheet K col */
  var INST_REPORT_CATS = [
    'COMP','DOCU','THRD','CHNG','PPPR','AAAI','DATA','APPL',
    'DCTR','FIDP','HFIH','VULN','CONS','HIPA','PCID','OPEM','ITAC'
  ];

  /* Privacy Analyst Evaluation category codes (in order) */
  var PRIV_REPORT_CATS = ['PRGN','PCOM','PDOC','PTHP','PCHG','PDAT','PRPO','INTL','DRPV','DPAI'];

  /* Full category names (from Auto Responses sheet) */
  var CAT_FULL = {
    COMP:'Company Information',                    DOCU:'Documentation',
    THRD:'Assessment of Third Parties',            CHNG:'Change Management',
    PPPR:'Policies, Processes, and Procedures',    AAAI:'Authentication, Authorization, and Account Management',
    DATA:'Data',                                   APPL:'Application/Service Security',
    DCTR:'Datacenter',                             FIDP:'Firewalls, IDS, IPS, and Networking',
    HFIH:'Incident Handling',                      VULN:'Vulnerability Management',
    CONS:'Consulting Services',                    HIPA:'HIPAA Compliance',
    PCID:'Payment Card Industry Data Security Standard (PCI DSS)',
    OPEM:'On-Premises Data Solutions',             ITAC:'IT Accessibility',
    PRGN:'General Privacy',                        PCOM:'Privacy-Specific Company Details',
    PDOC:'Privacy-Specific Documentation',         PTHP:'Privacy of Third Parties',
    PCHG:'Privacy Change Management',              PDAT:'Privacy of Sensitive Data',
    PRPO:'Privacy Policies and Procedures',        INTL:'International Privacy',
    DRPV:'Data Privacy',                           DPAI:'Privacy and AI',
  };

  /* Questions by category code */
  function qsByCat(catCode) {
    return HECVAT_QUESTIONS.filter(function(q) {
      return q.id.slice(0,4) === catCode && q.loc !== 'Not Scored' && q.score !== 'NA';
    });
  }

  /* Score a set of questions applying analyst overrides */
  function scoreQs(qs) {
    var earned = 0, pot = 0, comp = 0, nc = 0;
    qs.forEach(function(q) {
      var ae = AE[q.id] || {};
      var p  = ae.impOverride
        ? (ae.impOverride === 'Critical Importance' ? 20 : ae.impOverride === 'Minor Importance' ? 5 : 10)
        : pts(q.imp);
      if (!p) return;
      pot += p;
      var v = R[q.id] && R[q.id].value;
      if (!v) return;
      if (v === 'N/A') { pot -= p; return; }
      var ok;
      if (ae.compOverride === 'Mark as Compliant')     ok = true;
      else if (ae.compOverride === 'Mark as Non-Compliant') ok = false;
      else ok = q.comp ? v === q.comp : v === 'Yes';
      if (ok) { earned += p; comp++; } else { nc++; }
    });
    return { earned: earned, pot: pot, comp: comp, nc: nc,
             pct: pot > 0 ? Math.round(earned / pot * 100) : null };
  }

  /* ================================================================
     SHARED ANALYST ROW BUILDER
  ================================================================ */
  function vendorAnsBadge(qid) {
    var v = R[qid] && R[qid].value;
    var div = mk('div', 'vendor-ans');
    if (!v)          { div.className = 'vendor-ans none'; div.appendChild(txt('\u2014 Not yet answered')); return div; }
    if (v === 'Yes') { div.className = 'vendor-ans yes';  div.appendChild(txt('\u2713 Yes')); }
    else if (v === 'No')  { div.className = 'vendor-ans no';   div.appendChild(txt('\u2717 No')); }
    else if (v === 'N/A') { div.className = 'vendor-ans na';   div.appendChild(txt('\u2014 N/A')); }
    else { div.className = 'vendor-ans txt'; div.appendChild(txt(HECVAT_SEC.sanitize(v.length > 100 ? v.slice(0,100)+'\u2026' : v))); }
    return div;
  }

  function complianceBadge(q, overrideComp) {
    var v = R[q.id] && R[q.id].value;
    var div = mk('div', 'comp-badge');
    if (overrideComp === 'Mark as Compliant')     { div.className = 'comp-badge ok';  div.appendChild(txt('\u2713 Override: Compliant')); return div; }
    if (overrideComp === 'Mark as Non-Compliant') { div.className = 'comp-badge bad'; div.appendChild(txt('\u2717 Override: Non-Compliant')); return div; }
    if (!v) { div.className = 'comp-badge na'; div.appendChild(txt('Unanswered')); return div; }
    if (v === 'N/A') { div.className = 'comp-badge na'; div.appendChild(txt('N/A')); return div; }
    var ok = q.comp ? v === q.comp : v === 'Yes';
    div.className = ok ? 'comp-badge ok' : 'comp-badge bad';
    div.appendChild(txt(ok ? '\u2713 Compliant' : '\u2717 Non-Compliant'));
    return div;
  }

  function buildAnalystRow(q, evalId) {
    var ae   = AE[q.id] || {};
    var crit = q.imp === 'Critical Importance';
    var isNN = ae.nonNeg || false;

    var row = mk('div', 'arow' + (crit ? ' crit' : '') + (isNN ? ' non-neg' : ''));
    row.id = 'arow-' + evalId + '-' + q.id;
    attr(row, 'data-eval-qid', q.id);

    /* Left column */
    var L = mk('div');
    /* qmeta is given an ID so the Reason / Follow-up toggle below can
       reference it via aria-labelledby — that makes the toggle's
       accessible name include the question ID (e.g. "AAAI-01"),
       so screen-reader users can tell the otherwise-identical
       "+ Reason / Follow-up" buttons apart. */
    var metaId = 'aqmeta-' + evalId + '-' + q.id;
    var meta = mk('div', 'qmeta'); meta.id = metaId; meta.appendChild(txt(q.id));
    if (crit) { var bc = mk('span','bdg bdg-c'); bc.textContent='\u2605 Critical'; meta.appendChild(bc); }
    L.appendChild(meta);
    var qt = mk('div','qtext'); qt.id='aqt-'+evalId+'-'+q.id; qt.appendChild(txt(q.q)); L.appendChild(qt);

    /* Vendor answer + compliance */
    var ansWrap = mk('div'); attr(ansWrap,'aria-live','polite');
    ansWrap.id = 'avans-'+evalId+'-'+q.id;
    ansWrap.appendChild(vendorAnsBadge(q.id));
    ansWrap.appendChild(complianceBadge(q, ae.compOverride));
    L.appendChild(ansWrap);

    /* Reason / Follow-up */
    if (q.reason || q.followup) {
      var rtog = mk('button','reason-toggle'); rtog.type='button';
      attr(rtog,'aria-expanded','false');
      attr(rtog,'aria-controls','reason-'+evalId+'-'+q.id);
      attr(rtog,'data-reason-for', evalId+'-'+q.id);
      /* Accessible name = [the button's own "+ Reason / Follow-up" span]
         + [the qmeta div with the question ID and critical badge]. The
         browser concatenates the referenced text, so a screen reader
         announces e.g. "Plus Reason / Follow-up, AAAI-01 Critical,
         button, collapsed". That ID disambiguates every toggle on the
         page. */
      var rtogLblId = 'rtog-lbl-' + evalId + '-' + q.id;
      attr(rtog, 'aria-labelledby', rtogLblId + ' ' + metaId);
      var rtogLbl = mk('span'); rtogLbl.id = rtogLblId;
      rtogLbl.appendChild(txt('+ Reason / Follow-up'));
      rtog.appendChild(rtogLbl);
      L.appendChild(rtog);
      var rarea = mk('div','reason-area'); rarea.id='reason-'+evalId+'-'+q.id;
      if (q.reason)  { var rh=mk('strong'); rh.appendChild(txt('Reason for Question')); rarea.appendChild(rh); rarea.appendChild(txt(q.reason)); }
      if (q.followup){ var fh=mk('strong'); fh.appendChild(txt('Follow-up Guidance')); rarea.appendChild(fh); rarea.appendChild(txt(q.followup)); }
      L.appendChild(rarea);
    }

    /* Vendor notes */
    var vN = R[q.id] && R[q.id].notes;
    if (vN) {
      var vn = mk('div','qguide'); attr(vn,'role','note');
      var vnl = mk('strong'); vnl.appendChild(txt('Vendor notes: ')); vn.appendChild(vnl);
      vn.appendChild(txt(HECVAT_SEC.sanitize(vN))); L.appendChild(vn);
    }
    row.appendChild(L);

    /* Right column — analyst controls */
    var Ri = mk('div','analyst-fields');

    /* Importance Override */
    var impLbl = mk('label','analyst-label'); impLbl.htmlFor='ae-imp-'+evalId+'-'+q.id;
    impLbl.appendChild(txt('Importance Override'));
    var impSr = mk('span','sr-only'); impSr.appendChild(txt(' for '+q.id+': '+q.q)); impLbl.appendChild(impSr);
    Ri.appendChild(impLbl);
    var impSel = mk('select','analyst-select'+(ae.impOverride?' override-set':''));
    impSel.id='ae-imp-'+evalId+'-'+q.id;
    attr(impSel,'aria-label','Importance override for '+q.id+': '+q.q);
    attr(impSel,'aria-describedby','aqt-'+evalId+'-'+q.id);
    attr(impSel,'data-ae-qid',q.id); attr(impSel,'data-ae-field','impOverride');
    ['Default ('+(q.imp||'Unset')+')', 'Minor Importance','Standard Importance','Critical Importance'].forEach(function(o,i){
      var opt=document.createElement('option'); opt.value=i===0?'':o; opt.textContent=o;
      if ((ae.impOverride||'')===opt.value) opt.selected=true;
      impSel.appendChild(opt);
    });
    Ri.appendChild(impSel);

    /* Compliance Override */
    var compLbl = mk('label','analyst-label'); compLbl.htmlFor='ae-comp-'+evalId+'-'+q.id;
    compLbl.appendChild(txt('Compliance Override'));
    var compSr = mk('span','sr-only'); compSr.appendChild(txt(' for '+q.id+': '+q.q)); compLbl.appendChild(compSr);
    Ri.appendChild(compLbl);
    var compSel = mk('select','analyst-select'+(ae.compOverride?' override-set':''));
    compSel.id='ae-comp-'+evalId+'-'+q.id;
    attr(compSel,'aria-label','Compliance override for '+q.id+': '+q.q);
    attr(compSel,'aria-describedby','aqt-'+evalId+'-'+q.id);
    attr(compSel,'data-ae-qid',q.id); attr(compSel,'data-ae-field','compOverride');
    ['Default (Auto)','Mark as Compliant','Mark as Non-Compliant'].forEach(function(o,i){
      var opt=document.createElement('option'); opt.value=i===0?'':o; opt.textContent=o;
      if ((ae.compOverride||'')===opt.value) opt.selected=true;
      compSel.appendChild(opt);
    });
    Ri.appendChild(compSel);

    /* Live status for override changes — announced to screen readers */
    var overrideLive = mk('div','sr-only'); overrideLive.id='ae-live-'+evalId+'-'+q.id;
    attr(overrideLive,'aria-live','assertive'); attr(overrideLive,'aria-atomic','true');
    Ri.appendChild(overrideLive);

    /* Non-Negotiable */
    var nnRow = mk('div','non-neg-row'+(isNN?' checked':''));
    nnRow.id='ae-nn-row-'+evalId+'-'+q.id;
    var nnCb = document.createElement('input'); nnCb.type='checkbox'; nnCb.className='non-neg-cb';
    nnCb.id='ae-nn-'+evalId+'-'+q.id; nnCb.checked=isNN;
    attr(nnCb,'aria-label','Mark '+q.id+' as non-negotiable');
    attr(nnCb,'data-ae-qid',q.id); attr(nnCb,'data-ae-field','nonNeg');
    var nnLbl=mk('label'); nnLbl.htmlFor=nnCb.id; nnLbl.appendChild(txt('Non-Negotiable'));
    nnRow.appendChild(nnCb); nnRow.appendChild(nnLbl); Ri.appendChild(nnRow);

    /* Analyst Notes */
    var anLbl = mk('label','analyst-label'); anLbl.htmlFor='ae-notes-'+evalId+'-'+q.id;
    anLbl.appendChild(txt('Analyst Notes'));
    var anSr = mk('span','sr-only'); anSr.appendChild(txt(' for '+q.id)); anLbl.appendChild(anSr);
    Ri.appendChild(anLbl);
    var anTa = mk('textarea','analyst-notes-ta');
    anTa.id='ae-notes-'+evalId+'-'+q.id;
    attr(anTa,'aria-label','Analyst notes for '+q.id);
    attr(anTa,'data-ae-qid',q.id); attr(anTa,'data-ae-field','analystNotes');
    anTa.rows=2; anTa.value=ae.analystNotes||'';
    Ri.appendChild(anTa);

    row.appendChild(Ri);
    return row;
  }

  /* ================================================================
     SCORECARD TABLE BUILDER (shared)
  ================================================================ */
  function mkScorecardTable(id, ariaLabel) {
    var wrap = mk('div','eval-scorecard'); wrap.id='esc-'+id;
    var title = mk('div','eval-scorecard-title');
    title.appendChild(txt('Report Sections'));
    var sub = mk('span'); sub.id='esc-sub-'+id; sub.appendChild(txt('Updates as responses and overrides change'));
    title.appendChild(sub); wrap.appendChild(title);
    var tbl = mk('table','eval-sc-table'); attr(tbl,'role','table'); attr(tbl,'aria-label',ariaLabel);
    var thead = mk('thead'); var hrow = mk('tr');
    ['Report Section','Max Score','Score','Score %'].forEach(function(h){
      var th = mk('th'); attr(th, 'scope', 'col');
      th.appendChild(txt(h)); hrow.appendChild(th);
    });
    thead.appendChild(hrow); tbl.appendChild(thead);
    var tbody = mk('tbody'); tbody.id='esc-body-'+id; tbl.appendChild(tbody);
    var tfoot = mk('tfoot'); var frow = mk('tr','eval-overall-row'); frow.id='esc-total-'+id;
    var ftd = mk('td'); ftd.colSpan=4; ftd.appendChild(txt('Calculating\u2026')); frow.appendChild(ftd);
    tfoot.appendChild(frow); tbl.appendChild(tfoot);
    wrap.appendChild(tbl);
    return wrap;
  }

  function scorecardRow(label, sc) {
    var tr = mk('tr');
    var pct = sc.pct, bc = pct===null?'':pct>=80?'g':pct>=60?'o':'r';
    /* Row label — use <th scope="row"> so AT announces it as the row header */
    var th1 = mk('th','eval-sc-cat'); attr(th1, 'scope', 'row');
    th1.appendChild(txt(label)); tr.appendChild(th1);
    var td2=mk('td','eval-sc-pts'); td2.appendChild(txt(sc.pot+' pts')); tr.appendChild(td2);
    var td3=mk('td','eval-sc-pts'); td3.appendChild(txt(sc.earned+' pts')); tr.appendChild(td3);
    var td4=mk('td','eval-sc-pct '+bc); td4.appendChild(txt(pct!==null?pct+'%':'N/A')); tr.appendChild(td4);
    return tr;
  }

  function refreshTotalRow(id, earned, pot) {
    var frow = document.getElementById('esc-total-'+id);
    if (!frow) return;
    frow.replaceChildren();
    var pct = pot>0?Math.round(earned/pot*100):null;
    var bc  = pct===null?'':pct>=80?'g':pct>=60?'o':'r';
    /* Overall-score row spans the first two cols; still mark as a <th row> */
    var th1 = mk('th','eval-sc-cat'); attr(th1, 'scope', 'row');
    th1.colSpan=2; th1.appendChild(txt('Overall Score'));
    var td2=mk('td','eval-sc-pts'); td2.appendChild(txt(earned+' / '+pot+' pts'));
    var td3=mk('td','eval-sc-pct '+bc); td3.appendChild(txt(pct!==null?pct+'%':'N/A'));
    frow.appendChild(th1); frow.appendChild(td2); frow.appendChild(td3);
  }

  /* ================================================================
     INSTITUTION EVALUATION SCORECARD REFRESH
     Rows: one per category code (COMP→ITAC) + AI agg + Privacy agg + Overall
  ================================================================ */
  function refreshInstScorecard() {
    var tbody = document.getElementById('esc-body-inst-eval');
    if (!tbody) return;
    tbody.replaceChildren();
    var totalE=0, totalP=0;

    INST_REPORT_CATS.forEach(function(cat) {
      var qs = qsByCat(cat);
      var sc = scoreQs(qs);
      totalE+=sc.earned; totalP+=sc.pot;
      tbody.appendChild(scorecardRow((CAT_FULL[cat]||cat), sc));
    });

    /* AI aggregated — all scored AI-section questions */
    var aiQs = HECVAT_QUESTIONS.filter(function(q){ return q.sections.indexOf('ai')>-1 && q.loc!=='Not Scored' && q.score!=='NA'; });
    var aiSc = scoreQs(aiQs);
    totalE+=aiSc.earned; totalP+=aiSc.pot;
    tbody.appendChild(scorecardRow('AI (aggregated)', aiSc));

    /* Privacy aggregated — all scored privacy questions */
    var privQs = HECVAT_QUESTIONS.filter(function(q){ return q.sections.indexOf('privacy')>-1 && q.loc!=='Not Scored' && q.score!=='NA'; });
    var privSc = scoreQs(privQs);
    totalE+=privSc.earned; totalP+=privSc.pot;
    tbody.appendChild(scorecardRow('Privacy (aggregated)', privSc));

    refreshTotalRow('inst-eval', totalE, totalP);
  }

  /* ================================================================
     PRIVACY ANALYST SCORECARD REFRESH
     Rows: PRGN, PCOM, PDOC, PTHP, PCHG, PDAT, PRPO, INTL, DRPV, DPAI + Privacy Score
  ================================================================ */
  function refreshPrivacyScorecard() {
    var tbody = document.getElementById('esc-body-privacy-eval');
    if (!tbody) return;
    tbody.replaceChildren();
    var totalE=0, totalP=0;

    PRIV_REPORT_CATS.forEach(function(cat) {
      var qs = qsByCat(cat);
      var sc = scoreQs(qs);
      totalE+=sc.earned; totalP+=sc.pot;
      tbody.appendChild(scorecardRow((CAT_FULL[cat]||cat), sc));
    });

    refreshTotalRow('privacy-eval', totalE, totalP);
  }

  /* ================================================================
     HIGH-RISK SCORECARD REFRESH
     Two rows: Non-Negotiable | Critical Importance/Lite Score
  ================================================================ */
  function refreshHighRiskScorecard() {
    var tbody = document.getElementById('esc-body-high-risk');
    if (!tbody) return;
    tbody.replaceChildren();

    /* Non-Negotiable questions */
    var nnQs = HECVAT_QUESTIONS.filter(function(q){ return AE[q.id] && AE[q.id].nonNeg && q.loc!=='Not Scored'; });
    var nnSc = scoreQs(nnQs);
    var nnCnt = nnQs.length;
    var nnRow = mk('tr');
    var nnTh = mk('th','eval-sc-cat'); attr(nnTh, 'scope', 'row');
    nnTh.appendChild(txt('Non-Negotiable ('+(nnCnt)+' flagged)')); nnRow.appendChild(nnTh);
    var nn2=mk('td','eval-sc-pts'); nn2.appendChild(txt(nnSc.pot+' pts')); nnRow.appendChild(nn2);
    var nn3=mk('td','eval-sc-pts'); nn3.appendChild(txt(nnSc.earned+' pts')); nnRow.appendChild(nn3);
    var nnPct=nnSc.pct; var nnBc=nnPct===null?'':nnPct>=80?'g':nnPct>=60?'o':'r';
    var nn4=mk('td','eval-sc-pct '+nnBc); nn4.appendChild(txt(nnPct!==null?nnPct+'%':'N/A')); nnRow.appendChild(nn4);
    tbody.appendChild(nnRow);

    /* Critical Importance questions */
    var critQs = HECVAT_QUESTIONS.filter(function(q){ return q.imp==='Critical Importance' && q.loc!=='Not Scored'; });
    var critSc = scoreQs(critQs);
    var critRow = mk('tr');
    var critTh = mk('th','eval-sc-cat'); attr(critTh, 'scope', 'row');
    critTh.appendChild(txt('Critical Importance / Lite Score ('+critQs.length+' questions)')); critRow.appendChild(critTh);
    var c2=mk('td','eval-sc-pts'); c2.appendChild(txt(critSc.pot+' pts')); critRow.appendChild(c2);
    var c3=mk('td','eval-sc-pts'); c3.appendChild(txt(critSc.earned+' pts')); critRow.appendChild(c3);
    var cPct=critSc.pct; var cBc=cPct===null?'':cPct>=80?'g':cPct>=60?'o':'r';
    var c4=mk('td','eval-sc-pct '+cBc); c4.appendChild(txt(cPct!==null?cPct+'%':'N/A')); critRow.appendChild(c4);
    tbody.appendChild(critRow);

    /* Update non-negotiable count banner */
    var nnCountEl = document.getElementById('nn-count');
    if (nnCountEl) nnCountEl.textContent = String(nnCnt);
  }

  function refreshEvalScorecard(evalId) {
    if (evalId === 'inst-eval')    { refreshInstScorecard(); refreshCompliancePlotsIfOpen(); }
    else if (evalId === 'high-risk')    refreshHighRiskScorecard();
    else if (evalId === 'privacy-eval') refreshPrivacyScorecard();
  }

  /* Only re-render plots if their panel is currently expanded, to avoid
     wasted work on every keystroke while the user isn't looking at them. */
  function refreshCompliancePlotsIfOpen() {
    var tog = document.getElementById('compliance-plots-tog');
    if (tog && tog.getAttribute('aria-expanded') === 'true') renderCompliancePlots();
  }

  /* ================================================================
     HIGH-RISK PANEL: side-by-side Critical + Non-Negotiable lists
  ================================================================ */
  function buildHighRiskLists() {
    var wrap = mk('div'); wrap.id = 'hr-lists';
    wrap.className = 'hr-lists';

    /* Critical Importance column */
    var critCol = mk('div');
    var critHead = mk('h3','cat-hdr'); critHead.appendChild(txt('Critical Importance Questions'));
    var critCt = mk('span','cat-ct'); critCt.id='hr-crit-ct'; critCt.textContent='90'; critHead.appendChild(critCt);
    critCol.appendChild(critHead);

    var critList = mk('div'); critList.id='hr-crit-list';
    var critQs = HECVAT_QUESTIONS.filter(function(q){ return q.imp==='Critical Importance' && q.loc!=='Not Scored'; });
    critQs.forEach(function(q) {
      var row = mk('div', 'hr-item');
      var ae = AE[q.id]||{};
      var v = R[q.id]&&R[q.id].value;
      var ok = v ? (ae.compOverride==='Mark as Compliant'?true:ae.compOverride==='Mark as Non-Compliant'?false:(q.comp?v===q.comp:v==='Yes')) : null;
      var badge = mk('span','comp-badge hr-badge '+(v===null||v===undefined?'na':ok?'ok':'bad'));
      badge.appendChild(txt(!v?'--':v==='N/A'?'N/A':ok?'\u2713':'\u2717'));
      row.appendChild(badge);
      var idSpan = mk('span','hr-qid');
      idSpan.appendChild(txt(q.id));
      row.appendChild(idSpan);
      row.appendChild(txt(q.q.length>70?q.q.slice(0,70)+'\u2026':q.q));
      row.id = 'hr-crit-'+q.id;
      critList.appendChild(row);
    });
    critCol.appendChild(critList);
    wrap.appendChild(critCol);

    /* Non-Negotiable column */
    var nnCol = mk('div');
    var nnHead = mk('h3','cat-hdr'); nnHead.appendChild(txt('Non-Negotiable Questions'));
    var nnCt = mk('span','cat-ct'); nnCt.id='hr-nn-ct'; nnCt.textContent='0'; nnHead.appendChild(nnCt);
    nnCol.appendChild(nnHead);

    var nnList = mk('div'); nnList.id='hr-nn-list';
    var nnEmpty = mk('div', 'hr-empty');
    nnEmpty.id='hr-nn-empty'; nnEmpty.appendChild(txt('No non-negotiable questions flagged yet.'));
    nnList.appendChild(nnEmpty);
    nnCol.appendChild(nnList);
    wrap.appendChild(nnCol);
    return wrap;
  }

  function refreshHighRiskLists() {
    var nnList = document.getElementById('hr-nn-list'); if(!nnList) return;
    var nnEmpty = document.getElementById('hr-nn-empty');
    var nnCt = document.getElementById('hr-nn-ct');
    var nnQs = HECVAT_QUESTIONS.filter(function(q){ return AE[q.id]&&AE[q.id].nonNeg; });
    if (nnCt) nnCt.textContent = String(nnQs.length);
    if (nnEmpty) nnEmpty.classList.toggle('hidden', nnQs.length > 0);

    /* Remove old rows except empty notice */
    var existing = nnList.querySelectorAll('[id^="hr-nn-q-"]');
    existing.forEach(function(el){ el.remove(); });

    nnQs.forEach(function(q) {
      var row = mk('div', 'hr-item hr-nn-item'); row.id='hr-nn-q-'+q.id;
      var idSpan = mk('span','hr-qid hr-qid-red');
      idSpan.appendChild(txt(q.id)); row.appendChild(idSpan);
      row.appendChild(txt(q.q.length>70?q.q.slice(0,70)+'\u2026':q.q));
      nnList.appendChild(row);
    });

    /* Refresh critical row compliance indicators */
    var critQs = HECVAT_QUESTIONS.filter(function(q){ return q.imp==='Critical Importance'&&q.loc!=='Not Scored'; });
    critQs.forEach(function(q) {
      var row = document.getElementById('hr-crit-'+q.id); if(!row) return;
      var badge = row.querySelector('.comp-badge');
      if (!badge) return;
      var ae=AE[q.id]||{}; var v=R[q.id]&&R[q.id].value;
      var ok=v?(ae.compOverride==='Mark as Compliant'?true:ae.compOverride==='Mark as Non-Compliant'?false:(q.comp?v===q.comp:v==='Yes')):null;
      badge.className='comp-badge '+(v===null||v===undefined?'na':ok?'ok':'bad');
      badge.textContent=!v?'--':v==='N/A'?'N/A':ok?'\u2713':'\u2717';
    });
  }

  /* ================================================================
     VISUAL COMPLIANCE PLOTS (native SVG — no external libs, CSP-safe)

     Renders two complementary charts on the Institution Evaluation tab:

     1. Compliance proportion by category, with 95% Wilson-score
        confidence-interval error bars (so you can read whether two
        categories' compliance rates differ significantly — if the
        intervals don't overlap, the difference is significant).

     2. Stacked answer composition by category (Compliant / Non-Compliant
        / N-A / Unanswered) so you can see the volume of responses
        behind each compliance rate at a glance.
  ================================================================ */
  var SVG_NS = 'http://www.w3.org/2000/svg';
  function svgEl(tag, attrs) {
    var e = document.createElementNS(SVG_NS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }
  function svgText(content, attrs) {
    var t = svgEl('text', attrs || {});
    t.appendChild(document.createTextNode(content));
    return t;
  }

  /* Wilson score 95% CI for a proportion. Returns {lo, hi} in [0,1]. */
  function wilsonCI(successes, trials) {
    if (trials <= 0) return { lo: 0, hi: 0, p: 0 };
    var z = 1.96;
    var p = successes / trials;
    var denom = 1 + (z * z) / trials;
    var centre = (p + (z * z) / (2 * trials)) / denom;
    var half   = (z * Math.sqrt((p * (1 - p) + (z * z) / (4 * trials)) / trials)) / denom;
    return { lo: Math.max(0, centre - half),
             hi: Math.min(1, centre + half),
             p:  p };
  }

  /* Compute per-category answer counts from current responses R. */
  function computeCategoryStats() {
    var catMap = {};
    HECVAT_QUESTIONS.forEach(function (q) {
      if (q.loc === 'Not Scored' || q.score === 'NA') return;
      if (!(q.comp === 'Yes' || q.comp === 'No')) return; // only scorable yes/no questions
      var cat = q.id.slice(0, 4);
      if (!catMap[cat]) catMap[cat] = { comp: 0, nc: 0, na: 0, unans: 0, total: 0 };
      var v = R[q.id] && R[q.id].value;
      catMap[cat].total++;
      if (!v)                         catMap[cat].unans++;
      else if (v === 'N/A')           catMap[cat].na++;
      else if (v === q.comp)          catMap[cat].comp++;
      else                            catMap[cat].nc++;
    });
    return catMap;
  }

  function buildCompliancePlots() {
    var sec = mk('div', 'cat-sec stat-methods-ref');
    var h3  = mk('h3', 'cat-h3');
    var togBtn = mk('button', 'cat-tog'); togBtn.type = 'button';
    togBtn.id = 'compliance-plots-tog';
    var bodyId = 'compliance-plots-body';
    attr(togBtn, 'aria-expanded', 'false');
    attr(togBtn, 'aria-controls', bodyId);

    var togLbl = mk('span', 'cat-tog-lbl');
    togLbl.appendChild(txt('\uD83D\uDCC8 Compliance Plots \u2014 By Category (95% CI)'));
    togBtn.appendChild(togLbl);
    var togIcon = mk('span', 'cat-tog-icon'); attr(togIcon, 'aria-hidden', 'true');
    togIcon.textContent = '\u25B8'; togBtn.appendChild(togIcon);
    h3.appendChild(togBtn);
    sec.appendChild(h3);

    var body = mk('div', 'cat-body cat-collapsed plots-body');
    body.id = bodyId;
    attr(body, 'role', 'region');
    attr(body, 'aria-labelledby', 'compliance-plots-tog');

    var intro = mk('p', 'stat-intro');
    intro.appendChild(txt(
      'Each bar is the compliance proportion for that category\u2019s scorable ' +
      'Yes/No questions. The whiskers are the 95% Wilson-score confidence ' +
      'interval \u2014 if two categories\u2019 intervals do not overlap, the ' +
      'difference between their compliance rates is statistically significant ' +
      'at the 0.05 level. The second chart shows the raw answer composition ' +
      'behind each rate so you can judge whether a narrow interval is driven ' +
      'by a large sample or a very uniform response.'
    ));
    body.appendChild(intro);

    /* Each chart is wrapped in a <figure role="figure"> with a caption,
       zoom controls, and a visually-hidden-by-default data table the
       screen reader (and keyboard users) can expand to read the numbers
       directly. The SVG itself gets <title>+<desc> so assistive tech
       reading the graphic still gets a meaningful summary. */
    body.appendChild(buildPlotFigure({
      id: 'plot-ci',
      figCls: 'plot-wrap',
      caption: 'Compliance proportion by category (with 95% CI)',
      tableLabel: 'Compliance proportion by category, with Wilson 95% confidence intervals and standard error of the mean (SEM)',
    }));

    /* Chart 2 (stacked composition) gets its own legend attached directly
       to the figure so the swatches sit under the right chart. */
    var stackFig = buildPlotFigure({
      id: 'plot-stack',
      figCls: 'plot-wrap',
      caption: 'Answer composition by category',
      tableLabel: 'Answer composition by category, counts of compliant, non-compliant, N/A, and unanswered questions',
    });
    var stackLegend = mk('div', 'plot-legend plot-legend-inline');
    [
      ['plot-comp',   'Compliant'],
      ['plot-nc',     'Non-Compliant'],
      ['plot-na',     'N/A'],
      ['plot-unans',  'Unanswered'],
    ].forEach(function (e) {
      var li = mk('span', 'plot-legend-item');
      var sw = mk('span', 'plot-legend-sw ' + e[0]);
      attr(sw, 'aria-hidden', 'true');
      li.appendChild(sw); li.appendChild(txt(e[1])); stackLegend.appendChild(li);
    });
    stackFig.appendChild(stackLegend);
    body.appendChild(stackFig);

    body.appendChild(buildPlotFigure({
      id: 'plot-pairwise',
      figCls: 'plot-wrap',
      caption: 'Pairwise category comparisons (two-proportion z-test)',
      tableLabel: 'Pairwise compliance-rate comparisons between categories using a two-proportion z-test; p-values are Bonferroni-adjusted and rows where the adjusted p-value is below 0.05 are flagged as a significant difference',
    }));

    sec.appendChild(body);

    togBtn.addEventListener('click', function () {
      var open = togBtn.getAttribute('aria-expanded') === 'true';
      attr(togBtn, 'aria-expanded', String(!open));
      body.classList.toggle('cat-collapsed', open);
      togIcon.textContent = open ? '\u25B8' : '\u25BE';
      /* Render on first open, and on every subsequent open in case data changed */
      if (!open) renderCompliancePlots();
    });

    return sec;
  }

  /* Build one accessible plot figure: caption + toolbar (zoom in/out/reset
     + show-data-table) + host DIV that will receive the SVG + a hidden
     data-table wrapper the toolbar reveals. */
  function buildPlotFigure(cfg) {
    var fig = mk('figure', cfg.figCls);
    attr(fig, 'role', 'figure');

    var capId = cfg.id + '-cap';
    var cap = mk('figcaption', 'plot-title');
    cap.id = capId;
    cap.appendChild(txt(cfg.caption));
    attr(fig, 'aria-labelledby', capId);
    fig.appendChild(cap);

    /* Toolbar */
    var tbar = mk('div', 'plot-toolbar');
    attr(tbar, 'role', 'toolbar');
    attr(tbar, 'aria-label', 'Controls for ' + cfg.caption);

    function mkTbBtn(label, ariaLabel, action) {
      var b = mk('button', 'plot-tb-btn'); b.type = 'button';
      attr(b, 'aria-label', ariaLabel);
      attr(b, 'title', ariaLabel);
      b.appendChild(txt(label));
      b.addEventListener('click', action);
      return b;
    }

    var zoomLevel = 1;
    function applyZoom() {
      var host = document.getElementById(cfg.id);
      if (!host) return;
      host.style.setProperty('--plot-zoom', String(zoomLevel));
      var readout = document.getElementById(cfg.id + '-zoomlvl');
      if (readout) readout.textContent = Math.round(zoomLevel * 100) + '%';
    }

    tbar.appendChild(mkTbBtn('\u2212', 'Zoom out', function () {
      zoomLevel = Math.max(0.5, +(zoomLevel - 0.25).toFixed(2)); applyZoom();
    }));
    var zLvl = mk('span', 'plot-zoom-lvl'); zLvl.id = cfg.id + '-zoomlvl';
    attr(zLvl, 'aria-live', 'polite'); zLvl.appendChild(txt('100%'));
    tbar.appendChild(zLvl);
    tbar.appendChild(mkTbBtn('+', 'Zoom in', function () {
      zoomLevel = Math.min(3, +(zoomLevel + 0.25).toFixed(2)); applyZoom();
    }));
    tbar.appendChild(mkTbBtn('Reset', 'Reset zoom to 100%', function () {
      zoomLevel = 1; applyZoom();
    }));

    /* Data-table toggle */
    var tblWrapId = cfg.id + '-table-wrap';
    var tblBtn = mk('button', 'plot-tb-btn plot-tb-btn-data'); tblBtn.type = 'button';
    attr(tblBtn, 'aria-expanded', 'false');
    attr(tblBtn, 'aria-controls', tblWrapId);
    attr(tblBtn, 'aria-label', 'Show data table for ' + cfg.caption);
    tblBtn.appendChild(txt('View data as table'));
    tbar.appendChild(tblBtn);

    fig.appendChild(tbar);

    /* SVG host */
    var host = mk('div', 'plot-svg-host'); host.id = cfg.id;
    attr(host, 'tabindex', '0'); /* keyboard-focusable so screen-reader users
                                    can reach it and hear its aria-label */
    fig.appendChild(host);

    /* Data table wrapper (hidden by default) */
    var tblWrap = mk('div', 'plot-table-wrap');
    tblWrap.id = tblWrapId;
    attr(tblWrap, 'hidden', 'hidden');
    attr(tblWrap, 'aria-label', cfg.tableLabel);
    fig.appendChild(tblWrap);

    tblBtn.addEventListener('click', function () {
      var open = tblBtn.getAttribute('aria-expanded') === 'true';
      attr(tblBtn, 'aria-expanded', String(!open));
      if (open) {
        tblWrap.setAttribute('hidden', 'hidden');
        tblBtn.firstChild.textContent = 'View data as table';
        attr(tblBtn, 'aria-label', 'Show data table for ' + cfg.caption);
      } else {
        tblWrap.removeAttribute('hidden');
        tblBtn.firstChild.textContent = 'Hide data table';
        attr(tblBtn, 'aria-label', 'Hide data table for ' + cfg.caption);
      }
    });

    return fig;
  }

  /* Normal-distribution 2-sided p-value from a z statistic.
     Uses Abramowitz & Stegun 7.1.26 rational approximation of erf. */
  function zToPTwoSided(z) {
    var ab = Math.abs(z);
    var a1 =  0.254829592, a2 = -0.284496736, a3 =  1.421413741,
        a4 = -1.453152027, a5 =  1.061405429, p  =  0.3275911;
    var sign = 1;
    var x = ab / Math.SQRT2;
    var t = 1.0 / (1.0 + p * x);
    var y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    var erf = sign * y;
    var cdf = 0.5 * (1 + erf);
    return 2 * (1 - cdf);
  }

  /* Two-proportion z-test. Returns { z, p }. */
  function twoProportionZ(x1, n1, x2, n2) {
    if (n1 <= 0 || n2 <= 0) return { z: 0, p: 1 };
    var p1 = x1 / n1, p2 = x2 / n2;
    var pp = (x1 + x2) / (n1 + n2);           // pooled proportion
    var se = Math.sqrt(pp * (1 - pp) * (1 / n1 + 1 / n2));
    if (se === 0) return { z: 0, p: 1 };
    var z = (p1 - p2) / se;
    return { z: z, p: zToPTwoSided(z) };
  }

  /* Build a <defs> block containing four distinct fill patterns for the
     answer-composition stacks. Each pattern combines a solid background
     colour with a distinctive texture so the segments remain identifiable
     to users with color-vision deficiencies or in black-and-white prints.

         pat-comp   — solid green (no motif — "positive" reads cleanly)
         pat-nc     — red with diagonal stripes
         pat-na     — amber with dots
         pat-unans  — grey with crosshatch
  */
  function buildSegmentPatternDefs() {
    var defs = svgEl('defs');

    /* Helper: background rect + overlay content */
    function mkPattern(id, bg, contentFn) {
      var p = svgEl('pattern', {
        id: id, x: 0, y: 0, width: 8, height: 8,
        patternUnits: 'userSpaceOnUse'
      });
      p.appendChild(svgEl('rect', { x: 0, y: 0, width: 8, height: 8, fill: bg }));
      if (contentFn) contentFn(p);
      defs.appendChild(p);
    }

    mkPattern('pat-comp',  '#15803d'); // solid
    mkPattern('pat-nc',    '#b91c1c', function (p) {
      /* diagonal stripes */
      p.appendChild(svgEl('path', {
        d: 'M0,8 L8,0 M-2,2 L2,-2 M6,10 L10,6',
        stroke: '#5c0b0b', 'stroke-width': '2', fill: 'none'
      }));
    });
    mkPattern('pat-na',    '#b45309', function (p) {
      /* dots */
      p.appendChild(svgEl('circle', { cx: 2, cy: 2, r: 1.3, fill: '#fff7ed' }));
      p.appendChild(svgEl('circle', { cx: 6, cy: 6, r: 1.3, fill: '#fff7ed' }));
    });
    mkPattern('pat-unans', '#9a9a90', function (p) {
      /* crosshatch */
      p.appendChild(svgEl('path', {
        d: 'M0,8 L8,0 M0,0 L8,8',
        stroke: '#efefea', 'stroke-width': '1.5', fill: 'none'
      }));
    });

    return defs;
  }

  /* Patterns for the pairwise-significance heatmap: same visual vocabulary
     (stripes = non-compliance/significance, dots = borderline, solid =
     none) so colorblind viewers can still rank severity. */
  function buildPairwisePatternDefs() {
    var defs = svgEl('defs');
    function mkPattern(id, bg, contentFn) {
      var p = svgEl('pattern', {
        id: id, x: 0, y: 0, width: 8, height: 8,
        patternUnits: 'userSpaceOnUse'
      });
      p.appendChild(svgEl('rect', { x: 0, y: 0, width: 8, height: 8, fill: bg }));
      if (contentFn) contentFn(p);
      defs.appendChild(p);
    }
    mkPattern('pat-sig-ns',  '#ececea');  // solid grey — not significant
    mkPattern('pat-sig1',    '#fde68a', function (p) {
      /* amber with dots */
      p.appendChild(svgEl('circle', { cx: 2, cy: 2, r: 1.2, fill: '#78350f' }));
      p.appendChild(svgEl('circle', { cx: 6, cy: 6, r: 1.2, fill: '#78350f' }));
    });
    mkPattern('pat-sig2',    '#fb923c', function (p) {
      /* orange with diagonal stripes */
      p.appendChild(svgEl('path', {
        d: 'M0,8 L8,0 M-2,2 L2,-2 M6,10 L10,6',
        stroke: '#7c2d12', 'stroke-width': '1.75', fill: 'none'
      }));
    });
    mkPattern('pat-sig3',    '#b91c1c', function (p) {
      /* red with dense crosshatch */
      p.appendChild(svgEl('path', {
        d: 'M0,8 L8,0 M0,0 L8,8 M-2,2 L2,-2 M6,10 L10,6 M-2,6 L2,10 M6,-2 L10,2',
        stroke: '#3f0707', 'stroke-width': '1.5', fill: 'none'
      }));
    });
    return defs;
  }

  /* Write an accessible data table into the hidden <div> for a plot.
     caption is the <caption> text; headers is an array of TH strings;
     rows is an array-of-arrays of cell values (coerced via String). */
  function buildPlotDataTable(wrap, caption, headers, rows) {
    wrap.replaceChildren();
    if (!rows.length) {
      var empty = mk('p'); empty.appendChild(txt('No data available yet.'));
      wrap.appendChild(empty);
      return;
    }
    var tbl = mk('table', 'plot-table');
    var cap = mk('caption'); cap.appendChild(txt(caption)); tbl.appendChild(cap);
    var thead = mk('thead'); var trh = mk('tr');
    headers.forEach(function (h) { var th = mk('th'); attr(th, 'scope', 'col'); th.appendChild(txt(h)); trh.appendChild(th); });
    thead.appendChild(trh); tbl.appendChild(thead);
    var tbody = mk('tbody');
    rows.forEach(function (r) {
      var tr = mk('tr');
      r.forEach(function (cell, idx) {
        var el = idx === 0 ? mk('th') : mk('td');
        if (idx === 0) attr(el, 'scope', 'row');
        el.appendChild(txt(String(cell)));
        tr.appendChild(el);
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
  }

  /* (Re)render all plots into their SVG hosts + data tables using current
     responses. Each SVG gets a <title>+<desc> first-child pair (the
     accessible-name source for role="img") and each figure gets a
     hidden-by-default data table with the same information in tabular
     form so screen-reader and keyboard users get an equivalent view. */
  function renderCompliancePlots() {
    var host1 = document.getElementById('plot-ci');
    var host2 = document.getElementById('plot-stack');
    var host3 = document.getElementById('plot-pairwise');
    if (!host1 || !host2 || !host3) return;

    var tbl1 = document.getElementById('plot-ci-table-wrap');
    var tbl2 = document.getElementById('plot-stack-table-wrap');
    var tbl3 = document.getElementById('plot-pairwise-table-wrap');

    var stats = computeCategoryStats();
    var cats  = Object.keys(stats).filter(function (c) { return stats[c].total > 0; });
    cats.sort(function (a, b) {
      var pa = stats[a].total ? stats[a].comp / Math.max(1, stats[a].comp + stats[a].nc) : 0;
      var pb = stats[b].total ? stats[b].comp / Math.max(1, stats[b].comp + stats[b].nc) : 0;
      return pb - pa;
    });

    host1.replaceChildren(); host2.replaceChildren(); host3.replaceChildren();

    if (!cats.length) {
      var msg1 = mk('div', 'plot-empty'); msg1.appendChild(txt('No scorable categories yet \u2014 answer a few Yes/No questions to populate the chart.'));
      host1.appendChild(msg1);
      var msg2 = mk('div', 'plot-empty'); msg2.appendChild(txt('Nothing to stack yet.'));
      host2.appendChild(msg2);
      var msg3 = mk('div', 'plot-empty'); msg3.appendChild(txt('At least two answered categories needed for pairwise comparison.'));
      host3.appendChild(msg3);
      if (tbl1) tbl1.replaceChildren();
      if (tbl2) tbl2.replaceChildren();
      if (tbl3) tbl3.replaceChildren();
      return;
    }

    /* Pre-compute per-category statistics used by chart 1 and the table */
    var perCat = cats.map(function (cat) {
      var s = stats[cat];
      var answered = s.comp + s.nc;
      var ci = wilsonCI(s.comp, answered);
      /* SEM of a proportion: sqrt( p(1-p) / n ) */
      var sem = answered > 0 ? Math.sqrt(ci.p * (1 - ci.p) / answered) : null;
      return { cat: cat, stats: s, answered: answered, ci: ci, sem: sem };
    });

    /* ───── Chart 1: bars + 95% CI error bars ───── */
    var W = Math.max(560, 48 * cats.length + 100);
    var H = 320, PAD_L = 48, PAD_B = 70, PAD_T = 14, PAD_R = 14;
    var chartW = W - PAD_L - PAD_R;
    var chartH = H - PAD_T - PAD_B;
    var barW = Math.max(14, chartW / cats.length * 0.65);
    var step = chartW / cats.length;

    var svg = svgEl('svg', {
      'viewBox': '0 0 ' + W + ' ' + H,
      'role': 'img',
      'aria-labelledby': 'plot-ci-svg-title plot-ci-svg-desc',
      'class': 'plot-svg',
      'focusable': 'false'
    });
    /* <title> and <desc> MUST be first children for AT to pick them up. */
    var t1 = svgEl('title', { id: 'plot-ci-svg-title' });
    t1.textContent = 'Compliance proportion by category with 95% confidence intervals';
    svg.appendChild(t1);
    var d1 = svgEl('desc',  { id: 'plot-ci-svg-desc' });
    d1.textContent = 'Bar chart. ' + perCat.map(function (r) {
      if (r.answered === 0) return r.cat + ' has no answered scorable questions';
      return r.cat + ': ' + Math.round(r.ci.p * 100) + '% compliant, ' +
             '95% CI ' + Math.round(r.ci.lo * 100) + '% to ' + Math.round(r.ci.hi * 100) + '%, ' +
             'n equals ' + r.answered;
    }).join('. ') + '.';
    svg.appendChild(d1);

    for (var i = 0; i <= 4; i++) {
      var gy = PAD_T + chartH - (i / 4) * chartH;
      svg.appendChild(svgEl('line', { x1: PAD_L, x2: W - PAD_R, y1: gy, y2: gy, 'class': 'plot-grid' }));
      svg.appendChild(svgText((i * 25) + '%', { x: PAD_L - 6, y: gy + 3, 'text-anchor': 'end', 'class': 'plot-axis-lbl' }));
    }
    svg.appendChild(svgText('Compliance %', {
      x: 12, y: PAD_T + chartH / 2, 'text-anchor': 'middle',
      'class': 'plot-axis-title',
      transform: 'rotate(-90 12 ' + (PAD_T + chartH / 2) + ')'
    }));

    perCat.forEach(function (row, idx) {
      var cx = PAD_L + step * idx + step / 2;
      var barH = row.ci.p * chartH;
      var by = PAD_T + chartH - barH;
      var rect = svgEl('rect', { x: cx - barW / 2, y: by, width: barW, height: barH, 'class': 'plot-bar' });
      /* Per-bar tooltip — reads as accessible name when the bar is focused */
      var rt = svgEl('title');
      rt.textContent = row.cat + ': ' + Math.round(row.ci.p * 100) + '%, 95% CI ' +
        Math.round(row.ci.lo * 100) + '%\u2013' + Math.round(row.ci.hi * 100) + '%, n=' + row.answered;
      rect.appendChild(rt);
      svg.appendChild(rect);

      if (row.answered > 0) {
        var yHi = PAD_T + chartH - row.ci.hi * chartH;
        var yLo = PAD_T + chartH - row.ci.lo * chartH;
        svg.appendChild(svgEl('line', { x1: cx, x2: cx, y1: yHi, y2: yLo, 'class': 'plot-err' }));
        svg.appendChild(svgEl('line', { x1: cx - 6, x2: cx + 6, y1: yHi, y2: yHi, 'class': 'plot-err' }));
        svg.appendChild(svgEl('line', { x1: cx - 6, x2: cx + 6, y1: yLo, y2: yLo, 'class': 'plot-err' }));
      }

      var pctLbl = row.answered > 0 ? Math.round(row.ci.p * 100) + '%' : 'n/a';
      svg.appendChild(svgText(pctLbl, { x: cx, y: Math.max(PAD_T + 10, by - 6), 'text-anchor': 'middle', 'class': 'plot-val-lbl' }));

      var lbl = svgText(row.cat, {
        x: cx, y: PAD_T + chartH + 14, 'text-anchor': 'end', 'class': 'plot-axis-lbl',
        transform: 'rotate(-35 ' + cx + ' ' + (PAD_T + chartH + 14) + ')'
      });
      var fullName = (typeof CAT_FULL !== 'undefined' && CAT_FULL[row.cat]) || row.cat;
      var ttl = svgEl('title'); ttl.textContent = fullName + ' \u2014 n=' + row.answered;
      lbl.appendChild(ttl);
      svg.appendChild(lbl);
    });

    svg.appendChild(svgEl('line', { x1: PAD_L, x2: W - PAD_R, y1: PAD_T + chartH, y2: PAD_T + chartH, 'class': 'plot-axis-line' }));
    host1.appendChild(svg);

    /* Data table 1 */
    if (tbl1) {
      var rows1 = perCat.map(function (r) {
        return [
          r.cat + ' \u2014 ' + ((typeof CAT_FULL !== 'undefined' && CAT_FULL[r.cat]) || r.cat),
          r.answered,
          r.answered > 0 ? (r.ci.p * 100).toFixed(1) + '%' : 'n/a',
          r.sem !== null ? (r.sem * 100).toFixed(2) + '%' : 'n/a',
          r.answered > 0 ? (r.ci.lo * 100).toFixed(1) + '% \u2013 ' + (r.ci.hi * 100).toFixed(1) + '%' : 'n/a',
        ];
      });
      buildPlotDataTable(tbl1,
        'Compliance proportion by category with 95% Wilson CI and SEM',
        ['Category', 'n (answered)', 'Compliance %', 'SEM', '95% CI'],
        rows1);
    }

    /* ───── Chart 2: stacked composition ───── */
    var W2 = W, H2 = 260, PAD_L2 = 48, PAD_B2 = 70, PAD_T2 = 14, PAD_R2 = 14;
    var chartW2 = W2 - PAD_L2 - PAD_R2;
    var chartH2 = H2 - PAD_T2 - PAD_B2;
    var step2 = chartW2 / cats.length;
    var barW2 = Math.max(14, step2 * 0.65);

    var svg2 = svgEl('svg', {
      'viewBox': '0 0 ' + W2 + ' ' + H2,
      'role': 'img',
      'aria-labelledby': 'plot-stack-svg-title plot-stack-svg-desc',
      'class': 'plot-svg',
      'focusable': 'false'
    });
    var t2 = svgEl('title', { id: 'plot-stack-svg-title' });
    t2.textContent = 'Answer composition by category';
    svg2.appendChild(t2);
    var d2 = svgEl('desc', { id: 'plot-stack-svg-desc' });
    d2.textContent = 'Stacked bar chart. ' + cats.map(function (c) {
      var s = stats[c];
      return c + ' has ' + s.total + ' total questions: ' + s.comp + ' compliant, ' +
             s.nc + ' non-compliant, ' + s.na + ' N/A, ' + s.unans + ' unanswered';
    }).join('. ') + '.';
    svg2.appendChild(d2);

    /* Pattern definitions so each stack segment is distinguishable by shape
       as well as color (accessibility / color-blindness). */
    svg2.appendChild(buildSegmentPatternDefs());

    var maxN = cats.reduce(function (m, c) { return Math.max(m, stats[c].total); }, 1);
    for (var j = 0; j <= 4; j++) {
      var gy2 = PAD_T2 + chartH2 - (j / 4) * chartH2;
      svg2.appendChild(svgEl('line', { x1: PAD_L2, x2: W2 - PAD_R2, y1: gy2, y2: gy2, 'class': 'plot-grid' }));
      svg2.appendChild(svgText(String(Math.round((j / 4) * maxN)), { x: PAD_L2 - 6, y: gy2 + 3, 'text-anchor': 'end', 'class': 'plot-axis-lbl' }));
    }
    svg2.appendChild(svgText('Questions', {
      x: 12, y: PAD_T2 + chartH2 / 2, 'text-anchor': 'middle',
      'class': 'plot-axis-title',
      transform: 'rotate(-90 12 ' + (PAD_T2 + chartH2 / 2) + ')'
    }));

    cats.forEach(function (cat, idx) {
      var s = stats[cat];
      var cx = PAD_L2 + step2 * idx + step2 / 2;
      var segs = [
        { key: 'plot-comp',  pat: 'pat-comp',   n: s.comp,  label: 'compliant' },
        { key: 'plot-nc',    pat: 'pat-nc',     n: s.nc,    label: 'non-compliant' },
        { key: 'plot-na',    pat: 'pat-na',     n: s.na,    label: 'N/A' },
        { key: 'plot-unans', pat: 'pat-unans',  n: s.unans, label: 'unanswered' },
      ];
      var cum = 0;
      segs.forEach(function (seg) {
        if (seg.n <= 0) return;
        var segH = (seg.n / maxN) * chartH2;
        var segY = PAD_T2 + chartH2 - ((cum + seg.n) / maxN) * chartH2;
        var segEl = svgEl('rect', {
          x: cx - barW2 / 2, y: segY, width: barW2, height: segH,
          'class': 'plot-seg ' + seg.key,
          fill: 'url(#' + seg.pat + ')',
          stroke: '#1a1a1a', 'stroke-width': '0.5'
        });
        var st = svgEl('title'); st.textContent = cat + ': ' + seg.n + ' ' + seg.label; segEl.appendChild(st);
        svg2.appendChild(segEl);
        cum += seg.n;
      });
      svg2.appendChild(svgText('n=' + s.total, {
        x: cx, y: PAD_T2 + chartH2 - (s.total / maxN) * chartH2 - 4,
        'text-anchor': 'middle', 'class': 'plot-val-lbl'
      }));
      var lbl2 = svgText(cat, {
        x: cx, y: PAD_T2 + chartH2 + 14, 'text-anchor': 'end', 'class': 'plot-axis-lbl',
        transform: 'rotate(-35 ' + cx + ' ' + (PAD_T2 + chartH2 + 14) + ')'
      });
      var fullName2 = (typeof CAT_FULL !== 'undefined' && CAT_FULL[cat]) || cat;
      var ttl2 = svgEl('title'); ttl2.textContent = fullName2;
      lbl2.appendChild(ttl2); svg2.appendChild(lbl2);
    });
    svg2.appendChild(svgEl('line', { x1: PAD_L2, x2: W2 - PAD_R2, y1: PAD_T2 + chartH2, y2: PAD_T2 + chartH2, 'class': 'plot-axis-line' }));
    host2.appendChild(svg2);

    /* Data table 2 */
    if (tbl2) {
      var rows2 = cats.map(function (c) {
        var s = stats[c];
        return [
          c + ' \u2014 ' + ((typeof CAT_FULL !== 'undefined' && CAT_FULL[c]) || c),
          s.comp, s.nc, s.na, s.unans, s.total
        ];
      });
      buildPlotDataTable(tbl2,
        'Raw answer counts by category',
        ['Category', 'Compliant', 'Non-Compliant', 'N/A', 'Unanswered', 'Total'],
        rows2);
    }

    /* ───── Chart 3: pairwise category comparisons (two-proportion z-test) ─────
       For every pair of categories that both have answered>=1, compute a
       two-proportion z-test on compliance rate. Bonferroni-adjust the
       p-value (multiply by number of comparisons, cap at 1) to control the
       family-wise error rate. Render as a heatmap-style grid: rows = cats,
       cols = cats, cell shade = significance strength. */
    var eligible = perCat.filter(function (r) { return r.answered > 0; });
    if (eligible.length < 2) {
      var msg3b = mk('div', 'plot-empty');
      msg3b.appendChild(txt('At least two categories with answered questions needed.'));
      host3.appendChild(msg3b);
      if (tbl3) tbl3.replaceChildren();
      return;
    }
    var m = eligible.length;
    var nComparisons = m * (m - 1) / 2;
    var pairs = [];
    for (var ii = 0; ii < m; ii++) {
      for (var jj = ii + 1; jj < m; jj++) {
        var A = eligible[ii], B = eligible[jj];
        var test = twoProportionZ(A.stats.comp, A.answered, B.stats.comp, B.answered);
        var adj = Math.min(1, test.p * nComparisons);
        pairs.push({ a: A, b: B, z: test.z, p: test.p, padj: adj, sig: adj < 0.05 });
      }
    }

    /* Heatmap-style grid */
    var CELL = 38;
    var headPx = 84;   // left + top label band
    var W3 = headPx + m * CELL + 20;
    var H3 = headPx + m * CELL + 20;

    var svg3 = svgEl('svg', {
      'viewBox': '0 0 ' + W3 + ' ' + H3,
      'role': 'img',
      'aria-labelledby': 'plot-pw-svg-title plot-pw-svg-desc',
      'class': 'plot-svg',
      'focusable': 'false'
    });
    var t3 = svgEl('title', { id: 'plot-pw-svg-title' });
    t3.textContent = 'Pairwise compliance rate comparisons using a two-proportion z-test with Bonferroni adjustment';
    svg3.appendChild(t3);
    var d3 = svgEl('desc', { id: 'plot-pw-svg-desc' });
    var sigPairs = pairs.filter(function (p) { return p.sig; });
    d3.textContent = (sigPairs.length === 0)
      ? 'No statistically significant differences between category compliance rates after Bonferroni adjustment.'
      : sigPairs.length + ' of ' + pairs.length + ' pairs differ significantly (adjusted p less than 0.05): ' +
        sigPairs.map(function (p) { return p.a.cat + ' vs ' + p.b.cat + ', adjusted p equals ' + p.padj.toFixed(3); }).join('; ') + '.';
    svg3.appendChild(d3);
    svg3.appendChild(buildPairwisePatternDefs());

    /* Column labels (top) */
    eligible.forEach(function (r, i) {
      var cxL = headPx + i * CELL + CELL / 2;
      var lbl = svgText(r.cat, {
        x: cxL, y: headPx - 6, 'text-anchor': 'end', 'class': 'plot-axis-lbl',
        transform: 'rotate(-55 ' + cxL + ' ' + (headPx - 6) + ')'
      });
      svg3.appendChild(lbl);
    });
    /* Row labels (left) */
    eligible.forEach(function (r, i) {
      var cyL = headPx + i * CELL + CELL / 2 + 3;
      svg3.appendChild(svgText(r.cat, { x: headPx - 6, y: cyL, 'text-anchor': 'end', 'class': 'plot-axis-lbl' }));
    });

    /* Cells */
    for (var ri = 0; ri < m; ri++) {
      for (var ci2 = 0; ci2 < m; ci2++) {
        var x = headPx + ci2 * CELL;
        var y = headPx + ri * CELL;
        var cellCls = 'plot-pw-cell plot-pw-cell-empty';
        var cellPat = null;
        var label = '';
        var pairTitle = '';
        if (ri === ci2) {
          cellCls = 'plot-pw-cell plot-pw-cell-diag';
          label = '\u2500';
          pairTitle = eligible[ri].cat + ' (same category)';
        } else {
          /* Find the pair (symmetric) */
          var A2 = eligible[Math.min(ri, ci2)];
          var B2 = eligible[Math.max(ri, ci2)];
          var thePair = pairs.find(function (p) { return p.a === A2 && p.b === B2; });
          if (thePair) {
            if (thePair.padj < 0.001)      { cellCls = 'plot-pw-cell plot-pw-cell-sig3'; cellPat = 'pat-sig3'; }
            else if (thePair.padj < 0.01)  { cellCls = 'plot-pw-cell plot-pw-cell-sig2'; cellPat = 'pat-sig2'; }
            else if (thePair.padj < 0.05)  { cellCls = 'plot-pw-cell plot-pw-cell-sig1'; cellPat = 'pat-sig1'; }
            else                           { cellCls = 'plot-pw-cell plot-pw-cell-ns';   cellPat = 'pat-sig-ns'; }
            label = thePair.padj < 0.001 ? '***' : thePair.padj < 0.01 ? '**' : thePair.padj < 0.05 ? '*' : 'ns';
            pairTitle = A2.cat + ' vs ' + B2.cat + ' \u2014 adjusted p=' + thePair.padj.toFixed(3) +
              ' (raw p=' + thePair.p.toFixed(3) + ', z=' + thePair.z.toFixed(2) + ')';
          }
        }
        var rectAttrs = { x: x + 1, y: y + 1, width: CELL - 2, height: CELL - 2, 'class': cellCls };
        if (cellPat) rectAttrs.fill = 'url(#' + cellPat + ')';
        var rect3 = svgEl('rect', rectAttrs);
        var rt3 = svgEl('title'); rt3.textContent = pairTitle; rect3.appendChild(rt3);
        svg3.appendChild(rect3);
        if (label) {
          svg3.appendChild(svgText(label, {
            x: x + CELL / 2, y: y + CELL / 2 + 4, 'text-anchor': 'middle', 'class': 'plot-pw-lbl'
          }));
        }
      }
    }

    host3.appendChild(svg3);

    /* Key below the heatmap */
    var keyBar = mk('div', 'plot-pw-key');
    [
      ['plot-pw-cell-sig3', '*** p<0.001'],
      ['plot-pw-cell-sig2', '** p<0.01'],
      ['plot-pw-cell-sig1', '* p<0.05'],
      ['plot-pw-cell-ns',   'ns (not significant)'],
    ].forEach(function (kv) {
      var item = mk('span', 'plot-legend-item');
      var sw = mk('span', 'plot-legend-sw ' + kv[0]); attr(sw, 'aria-hidden', 'true');
      item.appendChild(sw); item.appendChild(txt(kv[1])); keyBar.appendChild(item);
    });
    host3.appendChild(keyBar);

    /* Data table 3 — every pair, with its adjusted p-value */
    if (tbl3) {
      var rows3 = pairs.map(function (p) {
        return [
          p.a.cat + ' vs ' + p.b.cat,
          Math.round(p.a.ci.p * 100) + '% (n=' + p.a.answered + ')',
          Math.round(p.b.ci.p * 100) + '% (n=' + p.b.answered + ')',
          p.z.toFixed(2),
          p.p.toFixed(3),
          p.padj.toFixed(3),
          p.sig ? 'Yes' : 'No'
        ];
      });
      buildPlotDataTable(tbl3,
        'Pairwise two-proportion z-test with Bonferroni adjustment. Bonferroni multiplier n equals ' + nComparisons,
        ['Pair', 'Rate A', 'Rate B', 'z', 'Raw p', 'Adjusted p', 'Significant at α=0.05?'],
        rows3);
    }
  }

  /* ================================================================
     BUILD ALL EVAL PANELS
  ================================================================ */
  function buildEvalSections() {
    var main = document.getElementById('main');
    var evalNav = document.getElementById('snav-eval');

    EVAL_SECS.forEach(function(es) {
      /* Nav button */
      var nb = mk('button','nb'); nb.type='button'; nb.id='nb-'+es.id;
      attr(nb,'aria-label',es.lbl+' evaluation section');
      attr(nb,'aria-current','false'); attr(nb,'data-sec',es.id);
      var dot=mk('span','nd'); attr(dot,'aria-hidden','true'); nb.appendChild(dot);
      nb.appendChild(txt(' '+es.lbl));
      evalNav.appendChild(nb);

      /* Panel */
      var panel = mk('section','panel'); panel.id='panel-'+es.id;
      attr(panel,'aria-labelledby','esh-'+es.id); attr(panel,'role','region'); attr(panel,'aria-hidden','true');

      /* Header */
      var hdr = mk('div','sec-hdr eval-hdr');
      var h2 = mk('h2'); h2.id='esh-'+es.id; h2.textContent=es.icon+' '+es.lbl; hdr.appendChild(h2);
      var desc = mk('p'); desc.textContent=es.desc; hdr.appendChild(desc);
      /* Print button for this eval panel */
      var prtBtn = mk('button','btn btn-ol');
      prtBtn.type = 'button';
      attr(prtBtn, 'aria-label', 'Print ' + es.lbl);
      prtBtn.appendChild(txt('\uD83D\uDDA8 Print this evaluation'));
      prtBtn.addEventListener('click', function() { window.print(); });
      hdr.appendChild(prtBtn);
      panel.appendChild(hdr);

      var body = mk('div','sec-body');

      /* Instructions */
      var inst = mk('div','eval-instructions'); attr(inst,'role','note');
      var instLines = {
        'inst-eval': ['Review vendor responses across all scored categories. Use override fields to adjust importance or compliance where context warrants.',
          'Non-Negotiable flags compile in the High-Risk Evaluation tab.',
          'Scores update in real time as vendor responses and analyst overrides change.'],
        'high-risk': ['This report shows the two condensed views: Critical Importance (Lite Score) questions and flagged Non-Negotiable questions.',
          'Flag questions as Non-Negotiable in the Institution Evaluation or Privacy Analyst Evaluation tabs.',
          'Changes cannot be made in this sheet — use the Institution Evaluation or Privacy Analyst Evaluation tabs.'],
        'privacy-eval': ['Review privacy-specific responses. Scores are broken out by each of the 10 privacy categories.',
          'Use Importance Override and Compliance Override to adjust scores where context warrants.',
          'All overrides synchronise with the Institution Evaluation scoring.'],
      };
      var instH = mk('strong');
      instH.appendChild(txt(es.id==='inst-eval'?'Instructions for Analysts':es.id==='high-risk'?'Instructions for High-Risk Scorecard':'Instructions for Privacy Analysts'));
      inst.appendChild(instH);
      (instLines[es.id]||[]).forEach(function(pt,i){
        var p=mk('p','inst-pt'); var n=mk('strong'); n.appendChild(txt((i+1)+'. ')); p.appendChild(n); p.appendChild(txt(pt)); inst.appendChild(p);
      });
      body.appendChild(inst);

      /* ── INSTITUTION EVALUATION ── */
      if (es.id === 'inst-eval') {
        body.appendChild(mkScorecardTable('inst-eval','Institution Evaluation Report Sections'));

        /* Visual compliance plots — collapsible, collapsed by default */
        body.appendChild(buildCompliancePlots());

        /* Expand/Collapse all button bar */
        var expandBar = mk('div','ie-expand-bar');
        var expAll = mk('button','btn btn-ol'); expAll.type='button'; expAll.appendChild(txt('Expand All'));
        var colAll = mk('button','btn btn-ol'); colAll.type='button'; colAll.appendChild(txt('Collapse All'));
        expAll.addEventListener('click', function() {
          body.querySelectorAll('.cat-body').forEach(function(b2){ b2.classList.remove('cat-collapsed'); });
          body.querySelectorAll('.cat-tog').forEach(function(t){ attr(t,'aria-expanded','true'); t.querySelector('.cat-tog-icon').textContent='\u25BE'; });
        });
        colAll.addEventListener('click', function() {
          body.querySelectorAll('.cat-body').forEach(function(b2){ b2.classList.add('cat-collapsed'); });
          body.querySelectorAll('.cat-tog').forEach(function(t){ attr(t,'aria-expanded','false'); t.querySelector('.cat-tog-icon').textContent='\u25B8'; });
        });
        expandBar.appendChild(expAll); expandBar.appendChild(colAll);
        body.appendChild(expandBar);

        /* Question rows by category — collapsible H3 using shared helper */
        INST_REPORT_CATS.forEach(function(cat) {
          var qs = qsByCat(cat);
          if (!qs.length) return;
          body.appendChild(mkCollapsible(CAT_FULL[cat]||cat, qs.length, function(b) {
            qs.forEach(function(q){ b.appendChild(buildAnalystRow(q,'inst-eval')); });
          }, 'ie-'+cat));
        });
        [
          { label:'AI (aggregated)', cat:'ai-agg', qs: HECVAT_QUESTIONS.filter(function(q){ return q.sections.indexOf('ai')>-1&&q.loc!=='Not Scored'&&q.score!=='NA'; }) },
          { label:'Privacy (aggregated)', cat:'priv-agg', qs: HECVAT_QUESTIONS.filter(function(q){ return q.sections.indexOf('privacy')>-1&&q.loc!=='Not Scored'&&q.score!=='NA'; }) },
        ].forEach(function(grp){
          if (!grp.qs.length) return;
          body.appendChild(mkCollapsible(grp.label, grp.qs.length, function(b) {
            grp.qs.forEach(function(q){ b.appendChild(buildAnalystRow(q,'inst-eval')); });
          }, 'ie-'+grp.cat));
        });
      }

      /* ── HIGH-RISK EVALUATION ── */
      else if (es.id === 'high-risk') {
        /* Non-negotiable summary banner */
        var nnBanner = mk('div','nn-summary'); nnBanner.id='nn-summary'; attr(nnBanner,'role','status'); attr(nnBanner,'aria-live','polite');
        var nnCnt2 = mk('div');
        var nnNum = mk('div','nn-count'); nnNum.id='nn-count'; nnNum.appendChild(txt('0'));
        var nnSub = mk('div','nn-sub'); nnSub.appendChild(txt('non-negotiable flags'));
        nnCnt2.appendChild(nnNum); nnCnt2.appendChild(nnSub);
        var nnLblDiv = mk('div');
        var nnL = mk('div','nn-summary-label'); nnL.appendChild(txt('Non-Negotiable Questions'));
        var nnD = mk('div','nn-desc');
        nnD.appendChild(txt('Flag questions using the Non-Negotiable checkbox in Institution Evaluation or Privacy Analyst Evaluation.'));
        nnLblDiv.appendChild(nnL); nnLblDiv.appendChild(nnD);
        nnBanner.appendChild(nnCnt2); nnBanner.appendChild(nnLblDiv);
        body.appendChild(nnBanner);

        body.appendChild(mkScorecardTable('high-risk','High-Risk Evaluation Report'));
        body.appendChild(buildHighRiskLists());
      }

      /* ── PRIVACY ANALYST EVALUATION ── */
      else if (es.id === 'privacy-eval') {
        body.appendChild(mkScorecardTable('privacy-eval','Privacy Analyst Evaluation Report Sections'));

        PRIV_REPORT_CATS.forEach(function(cat) {
          var qs = qsByCat(cat);
          if (!qs.length) return;
          body.appendChild(mkCollapsible(CAT_FULL[cat]||cat, qs.length, function(b) {
            qs.forEach(function(q){ b.appendChild(buildAnalystRow(q,'privacy-eval')); });
          }, 'pe-'+cat));
        });
      }

      panel.appendChild(body);
      main.appendChild(panel);
      refreshEvalScorecard(es.id);
    });

    /* ── DELEGATED EVENTS ── */
    main.addEventListener('change', function(e) {
      var qid   = e.target.getAttribute('data-ae-qid');
      var field = e.target.getAttribute('data-ae-field');
      if (!qid || !field) return;
      AE[qid] = AE[qid] || {};
      if (field === 'nonNeg') {
        AE[qid].nonNeg = e.target.checked;
        EVAL_SECS.forEach(function(es) {
          var row = document.getElementById('arow-'+es.id+'-'+qid);
          if (row) row.classList.toggle('non-neg', e.target.checked);
          var otherCb = document.getElementById('ae-nn-'+es.id+'-'+qid);
          if (otherCb && otherCb !== e.target) otherCb.checked = e.target.checked;
          var otherNnRow = document.getElementById('ae-nn-row-'+es.id+'-'+qid);
          if (otherNnRow) otherNnRow.classList.toggle('checked', e.target.checked);
        });
        refreshHighRiskScorecard();
        refreshHighRiskLists();
      } else {
        AE[qid][field] = e.target.value;
        e.target.classList.toggle('override-set', !!e.target.value);
        /* Announce override change to screen readers */
        EVAL_SECS.forEach(function(es) {
          var liveEl = document.getElementById('ae-live-'+es.id+'-'+qid);
          if (liveEl) {
            var msg = field === 'impOverride'
              ? 'Importance override for ' + qid + ': ' + (e.target.value || 'default')
              : 'Compliance override for ' + qid + ': ' + (e.target.value || 'default');
            liveEl.textContent = msg;
          }
        });
        /* Sync compliance badges */
        EVAL_SECS.forEach(function(es) {
          var ansWrap = document.getElementById('avans-'+es.id+'-'+qid);
          if (ansWrap) {
            ansWrap.replaceChildren();
            var q2 = HECVAT_QUESTIONS.find(function(x){ return x.id===qid; });
            if (q2) { ansWrap.appendChild(vendorAnsBadge(qid)); ansWrap.appendChild(complianceBadge(q2,AE[qid].compOverride)); }
          }
        });
      }
      EVAL_SECS.forEach(function(es){ refreshEvalScorecard(es.id); });
    });

    main.addEventListener('click', function(e) {
      var rtog = e.target.closest('[data-reason-for]');
      if (rtog) {
        var key = rtog.getAttribute('data-reason-for');
        var areaId = rtog.getAttribute('aria-controls');
        var area2  = document.getElementById(areaId);
        var open   = rtog.getAttribute('aria-expanded') === 'true';
        attr(rtog,'aria-expanded',String(!open));
        if (area2) area2.classList.toggle('on',!open);
        rtog.firstChild.textContent = open ? '+ Reason / Follow-up' : '\u2212 Reason / Follow-up';
      }
    });

    /* Eval nav */
    evalNav.addEventListener('click', function(e) {
      var b = e.target.closest('.nb'); if (!b) return;
      goTo(b.getAttribute('data-sec'));
    });
    evalNav.addEventListener('keydown', function(e) {
      if (e.key!=='ArrowDown'&&e.key!=='ArrowUp') return;
      var btns=[].slice.call(evalNav.querySelectorAll('.nb'));
      var i=btns.indexOf(document.activeElement); if(i===-1) return;
      var next=btns[e.key==='ArrowDown'?i+1:i-1];
      if (next) { next.focus(); e.preventDefault(); }
    });
  }

  /* Called when vendor responses change */
  function refreshEvalDisplays() {
    /* Refresh compliance badges in all eval rows */
    EVAL_SECS.forEach(function(es) {
      var rows = document.querySelectorAll('#panel-'+es.id+' [data-eval-qid]');
      rows.forEach(function(row) {
        var qid2 = row.getAttribute('data-eval-qid');
        var q2   = HECVAT_QUESTIONS.find(function(x){ return x.id===qid2; });
        var ansWrap = document.getElementById('avans-'+es.id+'-'+qid2);
        if (ansWrap && q2) {
          ansWrap.replaceChildren();
          ansWrap.appendChild(vendorAnsBadge(qid2));
          ansWrap.appendChild(complianceBadge(q2,(AE[qid2]||{}).compOverride));
        }
      });
      refreshEvalScorecard(es.id);
    });
    refreshHighRiskLists();
  }





  /* ================================================================
     INIT
  ================================================================ */
  document.getElementById('hdr-date').textContent = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  buildNav();
  buildSections();
  buildEvalSections();
  wireSidebarButtons();
  refreshProgress();

  /* ================================================================
     ACCESSIBILITY CONTROLS: DARK MODE + FONT SIZE
  ================================================================ */
  (function () {
    var html       = document.documentElement;
    var btnTheme   = document.getElementById('btn-theme');
    var btnFzUp    = document.getElementById('btn-fz-up');
    var btnFzDown  = document.getElementById('btn-fz-down');
    var fzDisplay  = document.getElementById('fz-display');

    var BASE_PX  = 15;
    var FZ_STEP  = 1;
    var FZ_MIN   = 11;
    var FZ_MAX   = 22;
    var LS_THEME = 'hecvat415_theme';
    var LS_FZ    = 'hecvat415_fz';

    function applyTheme(t) {
      html.setAttribute('data-theme', t);
      localStorage.setItem(LS_THEME, t);
      attr(btnTheme, 'aria-pressed', String(t === 'dark'));
      btnTheme.textContent = t === 'dark' ? '\u2600 Light' : '\uD83C\uDF19 Dark';
      btnTheme.classList.toggle('active', t === 'dark');
    }

    function currentFz() {
      /* Read from html element's computed font-size */
      var stored = parseInt(localStorage.getItem(LS_FZ), 10);
      return stored || BASE_PX;
    }

    function applyFz(px) {
      px = Math.max(FZ_MIN, Math.min(FZ_MAX, px));
      /* Set directly on html so ALL rem units in the page scale */
      html.style.fontSize = px + 'px';
      localStorage.setItem(LS_FZ, String(px));
      var pct = Math.round(px / BASE_PX * 100);
      if (fzDisplay) fzDisplay.textContent = pct + '%';
      if (btnFzDown) btnFzDown.disabled = (px <= FZ_MIN);
      if (btnFzUp)   btnFzUp.disabled   = (px >= FZ_MAX);
    }

    /* Apply saved or default prefs */
    var savedTheme = localStorage.getItem(LS_THEME);
    var savedFz    = parseInt(localStorage.getItem(LS_FZ), 10) || BASE_PX;

    if (!savedTheme) {
      /* Honour OS dark mode preference if user hasn't made a choice */
      try {
        var mq = window.matchMedia('(prefers-color-scheme: dark)');
        savedTheme = mq.matches ? 'dark' : 'light';
        mq.addEventListener('change', function (e) {
          if (!localStorage.getItem(LS_THEME)) applyTheme(e.matches ? 'dark' : 'light');
        });
      } catch (e) { savedTheme = 'light'; }
    }

    applyTheme(savedTheme);
    applyFz(savedFz);

    if (btnTheme)  btnTheme.addEventListener('click',  function () { applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'); });
    if (btnFzUp)   btnFzUp.addEventListener('click',   function () { applyFz(currentFz() + FZ_STEP); });
    if (btnFzDown) btnFzDown.addEventListener('click', function () { applyFz(currentFz() - FZ_STEP); });
    /* Double-click either A button to reset to default */
    if (btnFzUp)   btnFzUp.addEventListener('dblclick',   function () { localStorage.removeItem(LS_FZ); applyFz(BASE_PX); });
    if (btnFzDown) btnFzDown.addEventListener('dblclick', function () { localStorage.removeItem(LS_FZ); applyFz(BASE_PX); });
  }());

}());
