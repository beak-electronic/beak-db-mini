/* BEAK DB mini – Suche wie die Artikel-Datei (ArtikelFilter.cs): EIN Feld für BEAK-Nr. UND Volltext.
 * Volltext: alle Wörter (beliebige Reihenfolge) im normalisierten Index (Index-Text kommt fertig aus C#), Werte normalisiert
 * (2,2 = 2.2; 2K2 = 2,2K = 2.2k; 4R7; 100n = 100nF; µ/u), reine Zahlen nur an Zahlgrenzen, '*' = beliebige Zeichen.
 * Nur Ziffern (z. B. "1234" oder "1.234"): zuerst die Artikel, deren Nummer so beginnt (exakte Nummer oben), danach die Volltext-Treffer.
 */
'use strict';
var BeakSuche = (function () {
  const reEsc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  function normalisieren(s) {
    if (!s) return '';
    let t = s.toLowerCase().replace(/µ/g, 'u').replace(/Ω/g, 'r').replace(/ω/g, 'r').replace(/ohm/g, 'r');
    t = t.replace(/(?<=\d),(?=\d)/g, '.');
    t = t.replace(/(?<![\d.])(\d+)(k|m|r|n|u|p|g)(\d+)(?![\d.a-z])/g, '$1.$3$2');
    t = t.replace(/(?<=\d)\s*(k|m|r|n|u|p|g)(?:f|ohm|r)?(?![a-z])/g, '$1');
    return t;
  }
  function wort(w) {
    const n = normalisieren(w);
    // Ziffern mit Punkt ("200.", "200.4", "1.234"): Präfix der BEAK-Nr.; ohne Punkt am Ende zusätzlich als Wert (wie ArtikelFilter.cs)
    if (/^\d+(\.\d*)+$/.test(n)) {
      const z = n.replace(/\./g, ''), wert = n.endsWith('.') ? null : new RegExp('(?<![\\d.])' + reEsc(n) + '(?!\\d)');
      return h => h.startsWith(z) || (wert !== null && wert.test(h));
    }
    if (/^\d+(\.\d+)?$/.test(n)) { const rx = new RegExp('(?<![\\d.])' + reEsc(n)); return h => rx.test(h); }
    return h => h.includes(n);
  }
  // Index NUR aus BEAK-Nr. und Bezeichnung (Bernd 22.10.) – im Gerät selbst gebaut, damit auch ältere Datenbank-Dateien
  // (deren "x" noch Bemerkung/Sachmerkmale enthielt) richtig suchen. Entspricht ArtikelFilter.IndexTextIPad.
  const idx = new WeakMap();
  function index(a) {
    let h = idx.get(a);
    if (h === undefined) { const n = String(a.n); h = normalisieren(n + ' | ' + Number(a.n).toLocaleString('de-DE') + ' | ' + (a.b || '')); idx.set(a, h); }
    return h;
  }
  const woerter = e => (e || '').split(/\s+/).filter(Boolean);
  // v1.17 Werte-Modus (Bernd 30.10.): "2 k 2 w 5" → Zahl + einzeln stehende Einheit = EIN Wert (2k, 2W),
  // Werte und reine Zahlen dann GENAU (2k ≠ 2,2k / 22k, 5 = 5 bzw. 5%). Erkannt, sobald eine Einheit allein hinter einer Zahl steht.
  const EINH = /^(k|m|r|n|u|µ|p|g|w|kw|mw|v|kv|mv|a|ma|ua|%|f|nf|uf|pf|hz|khz|mhz|ohm|mr|h|mh|uh)$/i;
  function werteModus(ws) { for (let i = 1; i < ws.length; i++) if (EINH.test(ws[i]) && /^\d+([.,]\d+)?$/.test(ws[i - 1])) return true;
    if (ws.length > 1) for (const w of ws) { const m = /^\d+(?:[.,]\d+)?([a-zµ%]+)$/i.exec(w); if (m && EINH.test(m[1])) return true; }
    return false; }
  function werteWoerter(ws) {
    const r = [];
    for (let i = 0; i < ws.length; i++) {
      if (/^\d+([.,]\d+)?$/.test(ws[i]) && i + 1 < ws.length && EINH.test(ws[i + 1])) { r.push({ z: ws[i], e: ws[i + 1] }); i++; }
      else { const m = /^(\d+(?:[.,]\d+)?)([a-zµ%]+)$/i.exec(ws[i]); if (m && EINH.test(m[2])) r.push({ z: m[1], e: m[2] }); else r.push(ws[i]); }
    }
    return r.map(w => {
      if (typeof w === 'string') {
        if (/^\d+([.,]\d+)?$/.test(w)) { const n = normalisieren(w); const rx = new RegExp('(?<![\\d.])' + reEsc(n) + '(?![\\d.])'); return h => rx.test(h); }
        return w.includes('*') ? (rx => h => rx.test(h))(new RegExp(normalisieren(w).split('*').map(reEsc).join('.*'))) : wort(w);
      }
      const z = normalisieren(w.z), e = normalisieren('1' + w.e).slice(1);   // gleiche Einheiten-Schreibweise wie im Index
      const rx = new RegExp('(?<![\\d.])' + reEsc(z) + '\\s*' + reEsc(e) + (/[a-z]$/.test(e) ? '(?![a-z])' : ''));
      return h => rx.test(h);
    });
  }
  function muster(e) {
    const ws0 = woerter(e);
    if (werteModus(ws0)) { const pr = werteWoerter(ws0); return a => { const h = index(a); return pr.every(p => p(h)); }; }
    const pr = woerter(e).map(w => w.includes('*') ? (rx => h => rx.test(h))(new RegExp(normalisieren(w).split('*').map(reEsc).join('.*'))) : wort(w));
    return a => { const h = index(a); return pr.every(p => p(h)); };
  }
  function rang(e) {
    const ws = woerter(e); if (!ws.length) return () => 2;
    const erstes = normalisieren(ws[0].replace(/\*/g, '')), ziffern = ws[0].replace(/\D/g, '');
    const pr = ws.filter(w => !w.includes('*')).map(wort);
    return a => {
      const bez = normalisieren(a.b || '');
      if ((ws.length === 1 && ziffern.length > 0 && ziffern === ws[0].replace(/\./g, '') && String(a.n) === ziffern) || (erstes.length > 0 && bez.startsWith(erstes))) return 0;
      return pr.every(p => p(bez)) ? 1 : 2;
    };
  }
  const koll = new Intl.Collator('de-DE', { sensitivity: 'accent' });
  /** Volltext-Treffer in der Reihenfolge der Artikel-Datei (Rang, Bezeichnung, Nummer). */
  function volltext(liste, e) {
    if (!e.replace(/\*/g, '').trim()) return [];
    const f = muster(e), r = rang(e);
    return liste.filter(f).map(a => [a, r(a)]).sort((x, y) => x[1] - y[1] || koll.compare(x[0].b || '', y[0].b || '') || x[0].n - y[0].n).map(x => x[0]);
  }
  /** Ein Feld: BEAK-Nr. (Ziffern, Punkte erlaubt) und/oder Volltext. */
  function suche(liste, eingabe) {
    const e = (eingabe || '').trim(); if (!e) return liste.slice().sort((x, y) => x.n - y.n);
    const vt = volltext(liste, e);
    if (/^\d[\d.]*$/.test(e)) {
      const z = e.replace(/\./g, ''), nr = parseInt(z, 10);
      const nummer = liste.filter(a => String(a.n).startsWith(z)).sort((x, y) => (y.n === nr) - (x.n === nr) || x.n - y.n);
      const s = new Set(nummer); return nummer.concat(vt.filter(a => !s.has(a)));
    }
    return vt;
  }
  return { normalisieren, muster, rang, volltext, suche };
})();
if (typeof module !== 'undefined') module.exports = BeakSuche;
