/* hecvat-worker.js — HECVAT XLSX import worker
   Runs SheetJS in an isolated thread so a malformed/malicious
   xlsx cannot crash or exploit the main UI thread.
   Loaded as: new Worker('hecvat-worker.js')                   */
'use strict';

importScripts('xlsx.mini.min.js');

/* Sheet → primary question-category prefixes (same mapping as main app) */
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
Object.keys(SHEET_CATS).forEach(function(sheet) {
  SHEET_CATS[sheet].forEach(function(cat) { catToSheet[cat] = sheet; });
});

var QID_RE = /^[A-Z]{2,5}-\d{1,3}$/;

self.onmessage = function(e) {
  try {
    var workbook = XLSX.read(e.data, {
      type:        'array',
      cellFormula: false,   /* skip formula evaluation */
      cellHTML:    false,
      cellNF:      false,
      sheetStubs:  false,
      WTF:         false,
    });

    var map = {};

    Object.keys(SHEET_CATS).forEach(function(sheetName) {
      var ws = workbook.Sheets[sheetName];
      if (!ws) return;

      var data = XLSX.utils.sheet_to_json(ws, {
        header:    1,
        defval:    null,
        blankrows: false,
        raw:       false,
      });

      data.forEach(function(row) {
        var qid = row[0] ? String(row[0]).trim() : '';
        if (!QID_RE.test(qid)) return;

        /* Only accept from the primary sheet for this category */
        var cat = qid.slice(0, 4);
        if (catToSheet[cat] !== sheetName) return;

        var val   = row[2] != null ? String(row[2]).trim() : '';
        var notes = row[3] != null ? String(row[3]).trim() : '';

        /* Skip unresolved formula remnants */
        if (val.charAt(0) === '=') return;

        /* Normalise Yes/No/N/A casing */
        if (/^yes$/i.test(val))                           val = 'Yes';
        else if (/^no$/i.test(val))                       val = 'No';
        else if (/^n\/a$/i.test(val) || /^na$/i.test(val)) val = 'N/A';

        if (val || notes) {
          var entry = {};
          if (val)   entry.value = val;
          if (notes) entry.notes = notes;
          map[qid] = entry;
        }
      });
    });

    if (Object.keys(map).length === 0) {
      self.postMessage({
        success: false,
        error: 'No answers found. Make sure this is a completed HECVAT response file, not the blank template.',
      });
      return;
    }

    self.postMessage({ success: true, data: map });

  } catch (err) {
    self.postMessage({ success: false, error: 'Parse error: ' + err.message });
  }
};
