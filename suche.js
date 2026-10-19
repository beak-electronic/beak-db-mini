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
    if (/^\d+(\.\d+)?$/.test(n)) { const rx = new RegExp('(?<![\\d.])' + reEsc(n) + '(?![\\d]|\\.\\d)'); return h => rx.test(h); }
    return h => h.includes(n);
  }
  const woerter = e => (e || '').split(/\s+/).filter(Boolean);
  function muster(e) {
    const pr = woerter(e).map(w => w.includes('*') ? (rx => h => rx.test(h))(new RegExp(normalisieren(w).split('*').map(reEsc).join('.*'))) : wort(w));
    return a => pr.every(p => p(a.x || ''));
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
